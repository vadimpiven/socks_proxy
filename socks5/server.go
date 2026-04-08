// SPDX-License-Identifier: Apache-2.0 OR MIT

// Package socks5 implements an embeddable SOCKS5 proxy server (RFC 1928 / RFC 1929).
//
// # Quick start
//
// The simplest server accepts all connections without authentication:
//
//	srv, _ := socks5.NewServer(socks5.Config{})
//	srv.ListenAndServe(ctx, ":1080")
//
// Add username/password authentication with a single call:
//
//	srv, _ := socks5.NewServer(socks5.Config{
//	    Authenticators: []socks5.Authenticator{
//	        socks5.UserPassAuth("alice", "s3cr3t"),
//	    },
//	})
//
// Support multiple users:
//
//	srv, _ := socks5.NewServer(socks5.Config{
//	    Authenticators: []socks5.Authenticator{
//	        socks5.UserPassAuthMulti(map[string]string{
//	            "alice": "s3cr3t",
//	            "bob":   "hunter2",
//	        }),
//	    },
//	})
//
// # Supported SOCKS5 features
//
//   - CONNECT (0x01): TCP tunneling to IPv4, IPv6, and domain-name destinations
//   - UDP ASSOCIATE (0x03): datagram relay with SOCKS5 encapsulation;
//     fragmentation is not supported (RFC 1928 §7 permits dropping it)
//   - No-auth (0x00) and username/password (0x02) authentication (RFC 1929)
//   - Trusted-IP bypass ([Config.TrustedIPs])
//
// BIND (0x02) is rejected with reply 0x07 (command not supported).
// GSSAPI (method 0x01) is not implemented; clients that offer only GSSAPI
// receive reply 0xFF (no acceptable method). RFC 1928 §3 marks GSSAPI as
// MUST, but it is absent from virtually all deployed SOCKS5 implementations.
//
// # Access control
//
// The single [Config.AllowPrivateDestinations] flag governs whether CONNECT
// requests to private, loopback, and link-local addresses are permitted.
// When false (default), such connections receive reply 0x02 (not allowed),
// protecting against SSRF attacks in internet-facing deployments.
// Set true only when the proxy intentionally serves internal infrastructure.
//
// # Extension points
//
// Every component is replaceable through interfaces:
//   - [Authenticator] / [CredentialStore] — custom authentication logic
//   - [Resolver] — custom DNS resolution for the UDP relay path
//   - [DialFunc] — custom outbound TCP (proxy chaining, metrics, TLS, etc.)
package socks5

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Default timeout values used when the corresponding Config field is zero.
const (
	defaultHandshakeTimeout = 30 * time.Second
	defaultDialTimeout      = 30 * time.Second
	defaultTCPIdleTimeout   = 5 * time.Minute
	defaultUDPIdleTimeout   = 5 * time.Minute
	defaultDNSTimeout       = 5 * time.Second

	// gracefulDrainTime is the maximum time spent draining inbound data after
	// sending a failure reply. Not user-configurable: RFC 1928 §6 requires
	// the server to close within 10 s, and 2 s is a safe, fixed upper bound.
	gracefulDrainTime = 2 * time.Second

	defaultMaxConns = 1024
)

// Config holds all settings for a SOCKS5 server. All fields are read-only
// after being passed to [NewServer].
//
// A zero-value Config starts a proxy that requires no authentication and
// blocks CONNECT to private, loopback, and link-local IP destinations
// ([AllowPrivateDestinations] defaults to false). Set [AllowPrivateDestinations]
// to true for deployments that intentionally proxy to internal infrastructure.
type Config struct {
	// Logger receives all server-level and session-level log output.
	// Defaults to [slog.Default] when nil.
	Logger *slog.Logger

	// Authenticators is the ordered list of authentication methods offered to
	// clients. The server selects the first method the client also supports.
	//
	// For most servers, set exactly one entry using [UserPassAuth]:
	//
	//   Authenticators: []socks5.Authenticator{socks5.UserPassAuth("alice", "s3cr3t")}
	//
	// Leave nil (or empty) to accept unauthenticated connections.
	Authenticators []Authenticator

	// AllowPrivateDestinations permits CONNECT requests to private, loopback,
	// and link-local IP addresses (RFC 1918, 127.0.0.0/8, 169.254.0.0/16,
	// fc00::/7, fe80::/10, etc.).
	//
	// When false (default), such connections are rejected with reply 0x02
	// (not allowed), protecting internet-facing proxies against SSRF attacks.
	// Set true only when the proxy intentionally serves internal infrastructure
	// where private destinations are valid targets.
	//
	// Note: DOMAINNAME destinations (ATYP 0x03) are not filtered by this flag
	// because DNS resolution has not yet occurred at request time. Use a
	// validating [DialFunc] to protect against DNS-based SSRF.
	AllowPrivateDestinations bool

	// Resolver resolves domain names for the UDP ASSOCIATE relay path.
	// TCP CONNECT lets [Dial] handle DNS internally.
	// Defaults to [DefaultResolver] when nil.
	Resolver Resolver

	// Dial establishes outgoing TCP connections for CONNECT requests.
	// The context it receives already carries a deadline equal to DialTimeout.
	// Defaults to a [net.Dialer] bound to BindAddr (if set).
	//
	// Mutually exclusive with BindAddr: providing both is an error in [NewServer].
	Dial DialFunc

	// BindAddr pins all outgoing TCP connections to this local IP address
	// (e.g. "203.0.113.1" or "2001:db8::1"). Parsed and validated by [NewServer].
	//
	// Mutually exclusive with Dial: providing both is an error in [NewServer].
	BindAddr string

	// TrustedIPs lists client source addresses that bypass authentication even
	// when Authenticators require credentials. This is a static allowlist
	// evaluated at request time; it cannot be modified after [NewServer] returns.
	// IPv4 and IPv4-mapped IPv6 forms are normalised before comparison.
	TrustedIPs []netip.Addr

	// MaxConns limits concurrent client connections. Zero means 1024.
	MaxConns int

	// HandshakeTimeout limits the total time allowed for the greeting,
	// authentication, and request phases. Zero means 30 seconds.
	HandshakeTimeout time.Duration

	// DialTimeout limits the time for each outbound TCP connection.
	// Zero means 30 seconds.
	DialTimeout time.Duration

	// TCPIdleTimeout closes TCP relay connections idle for this long.
	// Zero means 5 minutes.
	TCPIdleTimeout time.Duration

	// UDPIdleTimeout tears down UDP associations idle for this long.
	// Zero means 5 minutes.
	UDPIdleTimeout time.Duration

	// DNSTimeout limits each DNS lookup performed by the UDP ASSOCIATE relay
	// for DOMAINNAME destinations. Zero means 5 seconds.
	DNSTimeout time.Duration
}

// Server is a ready-to-run SOCKS5 proxy. Create one with [NewServer], then
// call [Server.ListenAndServe] or [Server.Serve].
type Server struct {
	cfg      Config
	sem      chan struct{}
	timeouts serverTimeouts

	// Resolved interface values — always non-nil after NewServer.
	dial     DialFunc
	resolver Resolver

	// trustedIPs is a read-only set built from cfg.TrustedIPs in NewServer.
	// Because it is never written after construction, concurrent reads from
	// session goroutines are safe without a mutex.
	trustedIPs map[netip.Addr]struct{}
}

// serverTimeouts holds resolved (non-zero) timeout values for use at runtime.
type serverTimeouts struct {
	handshake time.Duration
	dial      time.Duration
	tcpIdle   time.Duration
	udpIdle   time.Duration
	dns       time.Duration
}

// NewServer creates a Server from cfg, validates the configuration, and fills
// in defaults for nil interface fields and zero timeout values.
//
// Returns an error when:
//   - Both Dial and BindAddr are set (mutually exclusive).
//   - BindAddr is non-empty but not a valid IP address.
//   - A [UserPassAuthenticator] has a nil [CredentialStore].
func NewServer(cfg Config) (*Server, error) {
	if cfg.Dial != nil && cfg.BindAddr != "" {
		return nil, fmt.Errorf("socks5: Dial and BindAddr are mutually exclusive; provide one or the other")
	}

	// Interface defaults.
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if len(cfg.Authenticators) == 0 {
		cfg.Authenticators = []Authenticator{NoAuthAuthenticator{}}
	}
	if cfg.Resolver == nil {
		cfg.Resolver = DefaultResolver{}
	}

	// Numeric defaults.
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = defaultMaxConns
	}

	// Timeout defaults: zero means "use the library default".
	to := serverTimeouts{
		handshake: cfg.HandshakeTimeout,
		dial:      cfg.DialTimeout,
		tcpIdle:   cfg.TCPIdleTimeout,
		udpIdle:   cfg.UDPIdleTimeout,
		dns:       cfg.DNSTimeout,
	}
	if to.handshake == 0 {
		to.handshake = defaultHandshakeTimeout
	}
	if to.dial == 0 {
		to.dial = defaultDialTimeout
	}
	if to.tcpIdle == 0 {
		to.tcpIdle = defaultTCPIdleTimeout
	}
	if to.udpIdle == 0 {
		to.udpIdle = defaultUDPIdleTimeout
	}
	if to.dns == 0 {
		to.dns = defaultDNSTimeout
	}

	// Validate every UserPassAuthenticator upfront to avoid a nil-dereference
	// panic on the first authentication attempt.
	for i, a := range cfg.Authenticators {
		if upa, ok := a.(UserPassAuthenticator); ok && upa.Credentials == nil {
			return nil, fmt.Errorf("socks5: Authenticators[%d] (UserPassAuthenticator) has a nil Credentials store", i)
		}
	}

	// Build the outbound dialer when the caller has not provided one.
	// The dial timeout is enforced via the per-call context in handleConnect;
	// net.Dialer.Timeout is not set here to avoid a redundant, confusing second
	// limit that would shadow the context deadline.
	var dial DialFunc
	if cfg.Dial != nil {
		dial = cfg.Dial
	} else {
		d := &net.Dialer{}
		if cfg.BindAddr != "" {
			parsed, err := netip.ParseAddr(cfg.BindAddr)
			if err != nil {
				return nil, fmt.Errorf("socks5: BindAddr %q is not a valid IP address: %w", cfg.BindAddr, err)
			}
			d.LocalAddr = &net.TCPAddr{IP: parsed.Unmap().AsSlice()}
		}
		dial = d.DialContext
	}

	// Build the read-only trusted-IP set from the static config.
	trusted := make(map[netip.Addr]struct{}, len(cfg.TrustedIPs))
	for _, ip := range cfg.TrustedIPs {
		trusted[ip.Unmap()] = struct{}{}
	}

	return &Server{
		cfg:        cfg,
		sem:        make(chan struct{}, cfg.MaxConns),
		timeouts:   to,
		dial:       dial,
		resolver:   cfg.Resolver,
		trustedIPs: trusted,
	}, nil
}

// ListenAndServe binds to addr and serves SOCKS5 connections until ctx is
// cancelled, then waits for all active sessions to finish.
//
// addr uses the same format as [net.Listen] (e.g. ":1080" or "[::]:1080").
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve accepts SOCKS5 connections on ln until ctx is cancelled. It closes
// the listener on shutdown and waits for all active sessions to finish.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	var (
		wg        sync.WaitGroup
		tempDelay time.Duration // backoff for transient accept errors
	)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			default:
			}
			// net.ErrClosed means the listener itself was closed by
			// external code (not via ctx); treat it as a permanent stop.
			if errors.Is(err, net.ErrClosed) {
				wg.Wait()
				return err
			}
			// Transient error (e.g. EMFILE – too many open files): back off
			// exponentially to avoid a hot CPU spin. Pattern mirrors net/http.
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
			}
			s.cfg.Logger.Warn("accept failed; retrying", "err", err, "delay", tempDelay)
			select {
			case <-time.After(tempDelay):
			case <-ctx.Done():
				wg.Wait()
				return nil
			}
			continue
		}
		tempDelay = 0

		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			conn.Close()
			wg.Wait()
			return nil
		default:
			s.cfg.Logger.Warn("connection limit reached, rejecting",
				"limit", s.cfg.MaxConns,
				"remote", conn.RemoteAddr())
			conn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-s.sem }()
			newSession(conn, s).handle(ctx)
		}()
	}
}

// isTrusted reports whether ip is in the static trusted-IP set.
// The set is read-only after NewServer, so no locking is needed.
func (s *Server) isTrusted(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	_, ok := s.trustedIPs[ip.Unmap()]
	return ok
}
