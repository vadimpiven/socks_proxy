// SPDX-License-Identifier: Apache-2.0 OR MIT

// udp.go implements the SOCKS5 UDP ASSOCIATE command (RFC 1928 §7).
//
// # Design summary
//
// Each UDP ASSOCIATE creates one PacketConn (the "relay socket") on a random
// port. The client is told to send its encapsulated UDP datagrams there.
//
// Direction detection uses a two-phase rule:
//
//	Phase 1 — client UDP address not yet known:
//	  • from.IP == clientTCPIP  →  client; learn the full address (IP:port)
//	  • otherwise              →  remote; drop (can't reply yet)
//
//	Phase 2 — client UDP address known:
//	  • from == clientUDPAddr (exact IP:port)  →  client
//	  • any other address                      →  remote
//
// This correctly handles remotes that reply from a different port than they
// listen on (e.g. NAT devices, load balancers), as well as the loopback case
// where client and remote share the same IP.
//
// Fragmentation (FRAG != 0x00) is not supported; such datagrams are dropped
// silently, as explicitly permitted by RFC 1928 §7.
//
// Lifetime: the association is torn down when the TCP control connection
// closes (monitored via io.Copy(io.Discard, …)) or the relay is idle for
// UDPIdleTimeout.
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
	"sync"
	"time"
)

const (
	// udpBufSize is the maximum UDP datagram size we handle. The IP/UDP
	// stack caps packets at ~65 507 bytes on IPv4.
	udpBufSize = 64 * 1024

	// udpResponseBufSize is the maximum size of a SOCKS5-wrapped UDP response:
	// the largest possible header (22 bytes) plus a full-size payload.
	udpResponseBufSize = 22 + udpBufSize
)

// handleUDPAssociate implements the SOCKS5 UDP ASSOCIATE command.
// The authoritative client IP is taken from the TCP control connection;
// the DST.ADDR hint in the request is intentionally ignored per RFC 1928 §7.
func (s *session) handleUDPAssociate(ctx context.Context) {
	if !s.ap.Addr().IsValid() {
		// Cannot enforce source-IP filtering without a known client IP.
		// In practice this only happens in tests using net.Pipe.
		_ = writeReply(s.conn, replyGeneralFailure, AddrSpec{})
		gracefulClose(s.conn)
		return
	}

	// Bind the relay socket on the same address family as the TCP connection.
	localTCP := s.conn.LocalAddr().(*net.TCPAddr)
	udpNet := "udp4"
	if localTCP.IP.To4() == nil {
		udpNet = "udp6"
	}

	pc, err := net.ListenPacket(udpNet, ":0")
	if err != nil {
		s.log.Warn("UDP: failed to create relay socket", "err", err)
		_ = writeReply(s.conn, replyGeneralFailure, AddrSpec{})
		gracefulClose(s.conn)
		return
	}
	// closePC ensures the PacketConn is closed exactly once regardless of
	// whether the association ends via idle timeout, TCP-connection close,
	// or server shutdown. Without Once, defer and the ctx goroutine race.
	var once sync.Once
	closePC := func() { once.Do(func() { pc.Close() }) }
	defer closePC()

	// Tell the client where to send UDP datagrams.
	// BND.ADDR = TCP local IP (the interface the client reaches us on).
	// BND.PORT = OS-assigned UDP relay port.
	relayPort := pc.LocalAddr().(*net.UDPAddr).Port
	localAP := localTCP.AddrPort()
	bound := AddrSpec{IP: localAP.Addr().Unmap(), Port: uint16(relayPort)}
	if err := writeReply(s.conn, replySuccess, bound); err != nil {
		return
	}

	s.log.Info("UDP association started", "relay_port", relayPort)

	// The association lives as long as both the TCP control connection and the
	// server context. Either cancels assocCtx, which unblocks the relay.
	assocCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer cancel()
		io.Copy(io.Discard, s.conn) //nolint:errcheck
	}()
	// When assocCtx is cancelled, unblock ReadFrom by closing the relay socket.
	go func() {
		<-assocCtx.Done()
		closePC()
	}()

	runUDPRelay(assocCtx, pc, s.ap.Addr(), s.srv.resolver, s.log, s.srv.timeouts.udpIdle, s.srv.timeouts.dns)
	s.log.Info("UDP association ended", "relay_port", relayPort)
}

// runUDPRelay is the core UDP relay loop.
//
//	client → relay  : parse SOCKS5 header, resolve dst, forward raw payload
//	remote → relay  : wrap payload in SOCKS5 header, forward to client
//
// Direction detection follows the two-phase rule described in the file header.
// Both buf (read buffer) and wbuf (write buffer) are allocated once per
// association to avoid per-packet heap pressure.
func runUDPRelay(
	ctx context.Context,
	pc net.PacketConn,
	clientIP netip.Addr,
	resolver Resolver,
	log *slog.Logger,
	idleTimeout time.Duration,
	dnsTimeout time.Duration,
) {
	buf := make([]byte, udpBufSize)
	wbuf := make([]byte, udpResponseBufSize) // reused for every remote→client response

	var (
		clientUDPAddr    net.Addr
		clientUDPAddrStr string
	)

	for {
		pc.SetReadDeadline(time.Now().Add(idleTimeout))

		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() && ctx.Err() == nil {
				log.Info("UDP relay idle timeout")
			}
			return
		}

		fromUDP := from.(*net.UDPAddr)
		fromAP := fromUDP.AddrPort()
		fromIP := fromAP.Addr().Unmap()

		// Classify the datagram as client→remote or remote→client.
		isClient := false
		if clientUDPAddr == nil {
			if fromIP == clientIP {
				clientUDPAddr = from
				clientUDPAddrStr = from.String()
				isClient = true
			}
		} else {
			isClient = (from.String() == clientUDPAddrStr)
		}

		if isClient {
			// Client → remote: strip the SOCKS5 header and forward.
			dest, payload, err := parseUDPHeader(buf[:n])
			if err != nil {
				log.Debug("UDP: dropping client datagram", "from", from, "err", err)
				continue
			}

			var dstAP netip.AddrPort
			if dest.Domain != "" {
				resolveCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
				ip, err := resolver.Resolve(resolveCtx, dest.Domain)
				cancel()
				if err != nil {
					log.Debug("UDP: failed to resolve destination", "domain", dest.Domain, "err", err)
					continue
				}
				dstAP = netip.AddrPortFrom(ip, dest.Port)
			} else {
				dstAP = dest.AddrPort()
			}

			if _, err := pc.WriteTo(payload, net.UDPAddrFromAddrPort(dstAP)); err != nil {
				log.Debug("UDP: forward to remote failed", "dst", dstAP, "err", err)
			}

		} else {
			// Remote → client: wrap payload in a SOCKS5 header and deliver.
			// Covers both same-host-different-port and entirely different hosts.
			if clientUDPAddr == nil {
				continue // client's UDP address not yet known; drop
			}
			rn := appendUDPResponse(wbuf, fromAP, buf[:n])
			if _, err := pc.WriteTo(wbuf[:rn], clientUDPAddr); err != nil {
				log.Debug("UDP: forward to client failed", "from", from, "err", err)
			}
		}
	}
}

// parseUDPHeader parses the SOCKS5 UDP request header (RFC 1928 §7):
//
//	+------+------+------+----------+----------+----------+
//	| RSV  | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+------+------+------+----------+----------+----------+
//	|  2   |  1   |  1   | Variable |    2     | Variable |
//	+------+------+------+----------+----------+----------+
//
// Fragmented datagrams (FRAG != 0x00) are rejected per RFC 1928 §7.
func parseUDPHeader(b []byte) (dest AddrSpec, payload []byte, err error) {
	if len(b) < 4 {
		return AddrSpec{}, nil, errors.New("UDP header too short")
	}
	if b[0] != 0x00 || b[1] != 0x00 {
		return AddrSpec{}, nil, fmt.Errorf("non-zero RSV in UDP header: [%#x %#x]", b[0], b[1])
	}
	if b[2] != 0x00 {
		return AddrSpec{}, nil, fmt.Errorf("fragmented UDP datagram (FRAG=%#x)", b[2])
	}
	dest, n, err := parseAddrFromBytes(b[3:])
	if err != nil {
		return AddrSpec{}, nil, fmt.Errorf("parse UDP destination: %w", err)
	}
	return dest, b[3+n:], nil
}
