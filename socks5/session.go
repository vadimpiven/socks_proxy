// SPDX-License-Identifier: Apache-2.0 OR MIT

// session.go drives one client connection through the full SOCKS5 pipeline:
//
//	negotiate auth → read request → rule check → dispatch (CONNECT / UDP ASSOCIATE)
//
// This file is internal to the package.
package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"
)

// session holds the state for one accepted client connection.
type session struct {
	conn net.Conn
	srv  *Server
	log  *slog.Logger   // pre-populated with "client" attribute; created once in newSession
	ap   netip.AddrPort // client's TCP address; .Addr() is already Unmap'd
}

// newSession constructs a session, extracting the client address once and
// building the per-session logger upfront so it is not recreated on every
// log call.
func newSession(conn net.Conn, srv *Server) *session {
	remoteAddr := conn.RemoteAddr()
	remote := remoteAddr.String()

	var ap netip.AddrPort
	if tcp, ok := remoteAddr.(*net.TCPAddr); ok {
		raw := tcp.AddrPort()
		ap = netip.AddrPortFrom(raw.Addr().Unmap(), raw.Port())
	}

	logger := srv.cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &session{
		conn: conn,
		srv:  srv,
		log:  logger.With("client", remote),
		ap:   ap,
	}
}

// isPrivateAddr reports whether addr falls into a non-routable address range
// that should not be reachable via a public SOCKS5 proxy.
func isPrivateAddr(addr netip.Addr) bool {
	ip := addr.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// handle drives the full SOCKS5 session pipeline to completion.
// ctx is the server's shutdown context; it is passed into dials and the UDP
// association so they are cancelled promptly when the server stops.
func (s *session) handle(ctx context.Context) {
	defer s.conn.Close()

	// A single deadline covers the entire handshake (greeting + auth +
	// request) to prevent slow-loris resource exhaustion.
	// SetDeadline can only fail if the connection is already closed, in which
	// case the next I/O call will surface the error. Safe to ignore here.
	_ = s.conn.SetDeadline(time.Now().Add(s.srv.timeouts.handshake))

	if err := s.negotiateAuth(); err != nil {
		s.log.Info("auth failed", "err", err)
		gracefulClose(s.conn)
		return
	}

	cmd, dest, err := s.readRequest()
	if err != nil {
		s.log.Info("bad request", "err", err)
		gracefulClose(s.conn)
		return
	}

	// Block CONNECT to private/loopback/link-local destinations unless the
	// operator explicitly permits it. The check applies only to CONNECT:
	// UDP ASSOCIATE's DST.ADDR is a client source-address hint (RFC 1928 §7),
	// not a forwarding target. Domain destinations are passed through because
	// DNS has not yet resolved at this point.
	if cmd == CommandConnect && !s.srv.cfg.AllowPrivateDestinations {
		if dest.IP.IsValid() && isPrivateAddr(dest.IP) {
			_ = writeReply(s.conn, replyNotAllowed, AddrSpec{})
			s.log.Info("request denied: private destination", "target", dest)
			gracefulClose(s.conn)
			return
		}
	}

	// Clear the handshake deadline before entering the data phase.
	// Same rationale as above: safe to ignore.
	_ = s.conn.SetDeadline(time.Time{})

	switch cmd {
	case CommandConnect:
		s.handleConnect(ctx, dest)
	case CommandUDPAssociate:
		s.handleUDPAssociate(ctx)
	default:
		_ = writeReply(s.conn, replyCmdNotSupported, AddrSpec{})
		s.log.Info("command not supported", "cmd", fmt.Sprintf("%#x", byte(cmd)))
		gracefulClose(s.conn)
	}
}

// negotiateAuth performs RFC 1928 §3 method negotiation followed by the
// sub-negotiation of the selected method.
//
// Trusted-IP bypass: a client whose source IP is in the static trusted set is
// offered NoAuth even when all configured authenticators require credentials,
// without allocating a temporary authenticator slice.
//
// Wire format — greeting:  VER(1) | NMETHODS(1) | METHODS(1-255)
// Wire format — selection: VER(1) | METHOD(1)
func (s *session) negotiateAuth() error {
	var hdr [2]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}
	if hdr[0] != version5 {
		return fmt.Errorf("unsupported SOCKS version: %#x", hdr[0])
	}
	if hdr[1] == 0 {
		// RFC 1928 §3: NMETHODS must be 1-255.
		_, _ = s.conn.Write([]byte{version5, methodNoAcceptable})
		return errors.New("NMETHODS is 0: client offered no methods (RFC 1928 §3)")
	}

	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(s.conn, methods); err != nil {
		return fmt.Errorf("read methods: %w", err)
	}

	// Trusted clients bypass credential-requiring authenticators: offer
	// NoAuth if the client supports it, without allocating a new slice.
	var selected Authenticator
	if s.srv.isTrusted(s.ap.Addr()) && slices.Contains(methods, methodNoAuth) {
		selected = NoAuthAuthenticator{}
	}
	if selected == nil {
		for _, a := range s.srv.cfg.Authenticators {
			if slices.Contains(methods, a.Code()) {
				selected = a
				break
			}
		}
	}

	if selected == nil {
		_, _ = s.conn.Write([]byte{version5, methodNoAcceptable})
		return errors.New("no acceptable authentication method")
	}

	if _, err := s.conn.Write([]byte{version5, selected.Code()}); err != nil {
		return fmt.Errorf("write method selection: %w", err)
	}

	identity, err := selected.Authenticate(s.conn)
	if err != nil {
		return err
	}
	if identity != "" {
		s.log.Info("authenticated", "user", identity)
	}
	return nil
}

// readRequest reads VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT and returns
// the command and destination. Protocol violations send a reply and return an
// error; unsupported commands are NOT rejected here — the caller dispatches.
func (s *session) readRequest() (Command, AddrSpec, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
		return 0, AddrSpec{}, fmt.Errorf("read request header: %w", err)
	}
	if hdr[0] != version5 {
		return 0, AddrSpec{}, fmt.Errorf("unexpected version in request: %#x", hdr[0])
	}
	// RFC 1928 §4: RSV must be 0x00.
	if hdr[2] != 0x00 {
		_ = writeReply(s.conn, replyGeneralFailure, AddrSpec{})
		return 0, AddrSpec{}, fmt.Errorf("non-zero RSV byte: %#x", hdr[2])
	}

	dest, err := readAddr(s.conn)
	if err != nil {
		code := replyGeneralFailure
		if errors.Is(err, errUnsupportedAddrType) {
			code = replyAddrNotSupported
		}
		_ = writeReply(s.conn, code, AddrSpec{})
		return 0, AddrSpec{}, fmt.Errorf("read destination: %w", err)
	}
	return Command(hdr[1]), dest, nil
}

// handleConnect dials the destination, sends the success reply, and relays
// data until both sides close.
func (s *session) handleConnect(ctx context.Context, dest AddrSpec) {
	dialCtx, dialCancel := context.WithTimeout(ctx, s.srv.timeouts.dial)
	defer dialCancel()

	remote, err := s.srv.dial(dialCtx, "tcp", dest.String())
	if err != nil {
		_ = writeReply(s.conn, replyFromError(err), AddrSpec{})
		s.log.Info("connect failed", "target", dest, "err", err)
		gracefulClose(s.conn)
		return
	}
	defer remote.Close()

	// Report the actual bound address to the client (RFC 1928 §6).
	// Use a safe assertion: a custom DialFunc may return a non-TCP conn
	// (e.g. a TLS or unix-socket wrapper); fall back to the zero AddrSpec
	// (0.0.0.0:0) rather than panicking.
	var bound AddrSpec
	if tcp, ok := remote.LocalAddr().(*net.TCPAddr); ok {
		ap := tcp.AddrPort()
		bound = AddrSpec{IP: ap.Addr().Unmap(), Port: ap.Port()}
	}
	if err := writeReply(s.conn, replySuccess, bound); err != nil {
		s.log.Warn("write success reply", "err", err)
		return
	}

	s.log.Info("relay started", "target", dest)
	if err := relay(s.conn, remote, s.srv.timeouts.tcpIdle); err != nil {
		s.log.Info("relay ended", "target", dest, "err", err)
		return
	}
	s.log.Info("relay ended", "target", dest)
}

// gracefulClose signals EOF to the peer (TCP half-close) then drains pending
// inbound data so close(2) sends a FIN rather than a RST.
//
// RFC 1928 §6: the server MUST terminate the connection within 10 s of
// sending a failure reply; we cap the drain at gracefulDrainTime (2 s).
func gracefulClose(conn net.Conn) {
	if hc, ok := conn.(halfCloser); ok {
		hc.CloseWrite()
	}
	conn.SetReadDeadline(time.Now().Add(gracefulDrainTime))
	io.Copy(io.Discard, conn)
}
