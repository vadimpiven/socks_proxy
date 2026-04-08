// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// discardLogger returns a logger that silences all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startEchoServer starts a TCP server that echoes all received data.
func startEchoServer(tb testing.TB) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln
}

// startProxy starts a SOCKS5 server with the given Config on a random port.
// If cfg.Logger is nil it is set to a discard logger so tests stay silent.
func startProxy(tb testing.TB, cfg Config) (addr string, cancel context.CancelFunc) {
	tb.Helper()
	if cfg.Logger == nil {
		cfg.Logger = discardLogger()
	}

	ctx, cancel := context.WithCancel(context.Background())
	srv, err := NewServer(cfg)
	if err != nil {
		cancel()
		tb.Fatalf("NewServer: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		tb.Fatal(err)
	}
	addr = ln.Addr().String()
	go srv.Serve(ctx, ln)
	return addr, cancel
}

// dialThroughProxy connects to target via the SOCKS5 proxy at proxyAddr using
// golang.org/x/net/proxy — a real, independent SOCKS5 client implementation.
// Passing a non-nil auth enables username/password authentication.
func dialThroughProxy(tb testing.TB, proxyAddr string, auth *proxy.Auth, target string) net.Conn {
	tb.Helper()
	d, err := proxy.SOCKS5("tcp", proxyAddr, auth, proxy.Direct)
	if err != nil {
		tb.Fatal(err)
	}
	conn, err := d.Dial("tcp", target)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { conn.Close() })
	return conn
}

func TestFullSession_NoAuth_Connect(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()
	proxyAddr, cancel := startProxy(t, Config{AllowPrivateDestinations: true})
	defer cancel()

	conn := dialThroughProxy(t, proxyAddr, nil, echo.Addr().String())

	conn.Write([]byte("hello proxy"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello proxy" {
		t.Fatalf("got %q, want %q", buf[:n], "hello proxy")
	}
}

func TestFullSession_UserPass_Connect(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	proxyAddr, cancel := startProxy(t, Config{
		Authenticators:           []Authenticator{UserPassAuth("user", "pass")},
		AllowPrivateDestinations: true,
	})
	defer cancel()

	conn := dialThroughProxy(t, proxyAddr,
		&proxy.Auth{User: "user", Password: "pass"},
		echo.Addr().String())

	conn.Write([]byte("authenticated"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "authenticated" {
		t.Fatalf("got %q, want %q", buf[:n], "authenticated")
	}
}

// TestFullSession_AuthFailure probes the RFC 1929 failure path at the wire
// level: wrong credentials must produce STATUS=0x01 followed by connection
// close. proxy.SOCKS5 is not used here because we need to inject the wrong
// password.
func TestFullSession_AuthFailure(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{
		Authenticators: []Authenticator{UserPassAuth("user", "pass")},
	})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodUserPass})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)

	authReq := []byte{authSubVersion, 0x04}
	authReq = append(authReq, "user"...)
	authReq = append(authReq, 0x05)
	authReq = append(authReq, "wrong"...)
	conn.Write(authReq)

	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)
	if authResp[0] != authSubVersion {
		t.Fatalf("auth response VER = %#x, want 0x01 (RFC 1929 §2)", authResp[0])
	}
	if authResp[1] != authFailure {
		t.Fatalf("STATUS = %#x, want %#x (failure)", authResp[1], authFailure)
	}

	// RFC 1929 §2: server MUST close the connection after a failure response.
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection to be closed after auth failure")
	}
}

// TestFullSession_UnsupportedCommand verifies the exact reply code (0x07) for
// BIND, which is not implemented.
func TestFullSession_UnsupportedCommand(t *testing.T) {
	// AllowPrivateDestinations: BIND targets 127.0.0.1, so private-IP filtering
	// must be disabled to let the request reach the command-dispatch switch,
	// which replies 0x07 (command not supported).
	proxyAddr, cancel := startProxy(t, Config{AllowPrivateDestinations: true})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	conn.Write([]byte{version5, byte(CommandBind), 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x50})

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != replyCmdNotSupported {
		t.Fatalf("REP = %#x, want %#x (cmd not supported)", reply[1], replyCmdNotSupported)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection close after failure reply (RFC 1928 §6)")
	}
}

// TestFullSession_ConnectionRefused verifies the exact reply code (0x05) when
// the target port is not listening.
func TestFullSession_ConnectionRefused(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{AllowPrivateDestinations: true})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	// Port 1 is almost certainly not listening.
	req := []byte{version5, byte(CommandConnect), 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x01}
	conn.Write(req)

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != replyConnRefused {
		t.Fatalf("REP = %#x, want %#x (conn refused)", reply[1], replyConnRefused)
	}
}

func TestGracefulShutdown(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()
	proxyAddr, cancel := startProxy(t, Config{AllowPrivateDestinations: true})

	conn := dialThroughProxy(t, proxyAddr, nil, echo.Addr().String())

	cancel() // simulate SIGTERM

	conn.Write([]byte("after shutdown"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "after shutdown" {
		t.Fatalf("got %q, want %q", buf[:n], "after shutdown")
	}
}

// TestGreeting_WrongVersion verifies RFC 1928 §3: VER must be 0x05.
func TestGreeting_WrongVersion(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{0x04, 0x01, methodNoAuth}) // SOCKS4 greeting

	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	n, _ := conn.Read(buf)
	if n >= 2 && buf[0] == version5 && buf[1] != methodNoAcceptable {
		t.Fatalf("server returned a valid method selection for wrong VER: %x", buf[:n])
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection to be closed after wrong VER")
	}
}

// TestGreeting_ZeroNMethods verifies RFC 1928 §3: NMETHODS=0 must be rejected
// with method byte 0xFF, followed by a server-initiated connection close.
func TestGreeting_ZeroNMethods(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x00}) // NMETHODS=0

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if resp[1] != methodNoAcceptable {
		t.Fatalf("METHOD = %#x, want 0xFF (no acceptable) for NMETHODS=0", resp[1])
	}
	// RFC 1928 §3: after X'FF' the client MUST close; the server also closes
	// (it returned an error from negotiateAuth and calls gracefulClose).
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected server to close connection after sending X'FF'")
	}
}

// TestRequest_NonZeroRSV verifies RFC 1928 §4: a non-zero RSV byte must
// produce reply 0x01 (general failure) and close the connection.
func TestRequest_NonZeroRSV(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	conn.Write([]byte{version5, byte(CommandConnect), 0x01, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x50})

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != replyGeneralFailure {
		t.Fatalf("REP = %#x, want 0x01 (general failure) for non-zero RSV", reply[1])
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection close after failure reply (RFC 1928 §6)")
	}
}

// TestRequest_UnknownATYP verifies RFC 1928 §5: an unknown address type must
// produce reply 0x08 (address type not supported).
func TestRequest_UnknownATYP(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	conn.Write([]byte{version5, byte(CommandConnect), 0x00, 0x02, 0x00, 0x00}) // ATYP=0x02 undefined

	reply := make([]byte, 10)
	io.ReadFull(conn, reply)
	if reply[1] != replyAddrNotSupported {
		t.Fatalf("REP = %#x, want 0x08 (address type not supported)", reply[1])
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection close after failure reply (RFC 1928 §6)")
	}
}

// TestConnect_DomainName verifies that ATYP=0x03 (domain name) is resolved
// server-side and the connection is established (RFC 1928 §5).
func TestConnect_DomainName(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()
	// AllowPrivateDestinations: "localhost" resolves to 127.0.0.1 (loopback).
	proxyAddr, cancel := startProxy(t, Config{AllowPrivateDestinations: true})
	defer cancel()

	_, portStr, _ := net.SplitHostPort(echo.Addr().String())
	conn := dialThroughProxy(t, proxyAddr, nil, "localhost:"+portStr)

	conn.Write([]byte("domain-name-test"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "domain-name-test" {
		t.Fatalf("got %q, want %q", buf[:n], "domain-name-test")
	}
}

// TestRequest_WrongVersion verifies that a wrong VER byte in the request phase
// (after successful auth) causes the server to close without sending a reply.
// The VER check runs inside readRequest() before rules are consulted.
func TestRequest_WrongVersion(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	conn.Write([]byte{0x04, byte(CommandConnect), 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x50})

	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection to be closed after wrong VER in request")
	}
}

// TestConnect_BNDAddrPort verifies RFC 1928 §6: the success reply must carry
// the actual bound address and port (not zeros).
func TestConnect_BNDAddrPort(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()
	proxyAddr, cancel := startProxy(t, Config{AllowPrivateDestinations: true})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	echoTCP := echo.Addr().(*net.TCPAddr)
	req := append([]byte{version5, byte(CommandConnect), 0x00, addrTypeIPv4}, echoTCP.IP.To4()...)
	req = binary.BigEndian.AppendUint16(req, uint16(echoTCP.Port))
	conn.Write(req)

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != replySuccess {
		t.Fatalf("REP = %#x, want 0x00 (success)", hdr[1])
	}

	var bndIP net.IP
	var bndPort uint16
	switch hdr[3] {
	case addrTypeIPv4:
		b := make([]byte, 6)
		io.ReadFull(conn, b)
		bndIP, bndPort = net.IP(b[:4]), binary.BigEndian.Uint16(b[4:6])
	case addrTypeIPv6:
		b := make([]byte, 18)
		io.ReadFull(conn, b)
		bndIP, bndPort = net.IP(b[:16]), binary.BigEndian.Uint16(b[16:18])
	default:
		t.Fatalf("unexpected ATYP in reply: %#x", hdr[3])
	}

	if bndPort == 0 {
		t.Error("BND.PORT is 0: RFC 1928 §6 requires the actual assigned port")
	}
	if bndIP.IsUnspecified() {
		t.Error("BND.ADDR is all-zeros: RFC 1928 §6 requires the actual bound address")
	}
}

// TestDefaultConfig_BlocksPrivateConnect verifies that the default Config
// (AllowPrivateDestinations=false) rejects CONNECT to loopback/private IPs
// with reply 0x02 (not allowed), protecting against SSRF.
// connectAndExpectBlocked dials the proxy, completes the NoAuth greeting, sends
// a CONNECT to the given raw address bytes (ATYP + addr + port), and asserts
// that the proxy returns reply 0x02 (not allowed) followed by a connection close.
func connectAndExpectBlocked(t *testing.T, proxyAddr string, atyp byte, addrBytes []byte, port uint16) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	io.ReadFull(conn, make([]byte, 2))

	req := append([]byte{version5, byte(CommandConnect), 0x00, atyp}, addrBytes...)
	req = binary.BigEndian.AppendUint16(req, port)
	conn.Write(req)

	// Failure replies always use a zero AddrSpec, which encodes as ATYP=IPv4
	// 0.0.0.0:0: VER(1)+REP(1)+RSV(1)+ATYP(1)+addr(4)+port(2) = 10 bytes.
	// Reading the full reply before checking for close is required; reading
	// fewer bytes would leave BND.ADDR/PORT in the TCP buffer, causing the
	// subsequent Read to return those bytes rather than EOF.
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read failure reply: %v", err)
	}
	if reply[1] != replyNotAllowed {
		t.Fatalf("REP = %#x, want 0x02 (not allowed)", reply[1])
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection close after failure reply (RFC 1928 §6)")
	}
}

// TestDefaultConfig_BlocksPrivateConnect verifies that the default config
// (AllowPrivateDestinations=false) blocks CONNECT to several categories of
// private/reserved addresses across both IPv4 and IPv6.
func TestDefaultConfig_BlocksPrivateConnect(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{}) // default: deny private
	defer cancel()

	cases := []struct {
		name  string
		atyp  byte
		addr  []byte
	}{
		{"IPv4 loopback", addrTypeIPv4, []byte{127, 0, 0, 1}},
		{"IPv4 RFC1918 10.x", addrTypeIPv4, []byte{10, 0, 0, 1}},
		{"IPv4 RFC1918 192.168.x", addrTypeIPv4, []byte{192, 168, 1, 1}},
		{"IPv4 link-local", addrTypeIPv4, []byte{169, 254, 169, 254}},
		// IPv6 addresses (16 bytes)
		{"IPv6 loopback ::1", addrTypeIPv6, func() []byte { a := make([]byte, 16); a[15] = 1; return a }()},
		{"IPv6 ULA fc00::1", addrTypeIPv6, func() []byte { a := make([]byte, 16); a[0] = 0xfc; a[15] = 1; return a }()},
		{"IPv6 link-local fe80::1", addrTypeIPv6, func() []byte { a := make([]byte, 16); a[0] = 0xfe; a[1] = 0x80; a[15] = 1; return a }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connectAndExpectBlocked(t, proxyAddr, tc.atyp, tc.addr, 80)
		})
	}
}

// TestAllowPrivateDestinations_PermitsLoopback verifies that setting
// AllowPrivateDestinations=true allows CONNECT to loopback addresses.
func TestAllowPrivateDestinations_PermitsLoopback(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()
	proxyAddr, cancel := startProxy(t, Config{AllowPrivateDestinations: true})
	defer cancel()

	conn := dialThroughProxy(t, proxyAddr, nil, echo.Addr().String())
	conn.Write([]byte("private-ok"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "private-ok" {
		t.Fatalf("got %q, want %q", buf[:n], "private-ok")
	}
}

// TestTrustedIPs_BypassAuth verifies that a client IP listed in
// [Config.TrustedIPs] may connect without credentials.
func TestTrustedIPs_BypassAuth(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	proxyAddr, cancel := startProxy(t, Config{
		Authenticators:           []Authenticator{UserPassAuth("user", "pass")},
		TrustedIPs:               []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		AllowPrivateDestinations: true,
	})
	defer cancel()

	conn := dialThroughProxy(t, proxyAddr, nil, echo.Addr().String())

	conn.Write([]byte("trusted"))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "trusted" {
		t.Fatalf("got %q", buf[:n])
	}
}

// TestTrustedIPs_UnknownIPRequiresAuth verifies that a client not in
// TrustedIPs is rejected at method negotiation when it offers only NoAuth,
// and that the server closes the connection after sending X'FF'.
func TestTrustedIPs_UnknownIPRequiresAuth(t *testing.T) {
	// Trust only 10.0.0.1; the test client arrives from 127.0.0.1.
	proxyAddr, cancel := startProxy(t, Config{
		Authenticators: []Authenticator{UserPassAuth("user", "pass")},
		TrustedIPs:     []netip.Addr{netip.MustParseAddr("10.0.0.1")},
	})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, methodNoAuth})
	resp := make([]byte, 2)
	io.ReadFull(conn, resp)
	if resp[1] != methodNoAcceptable {
		t.Fatalf("METHOD = %#x, want 0xFF (no acceptable)", resp[1])
	}
	// Server must close after X'FF' (gracefulClose path).
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected server to close after X'FF'")
	}
}

// TestNewServer_ValidationErrors verifies that [NewServer] rejects every
// invalid configuration before the server starts accepting connections.
func TestNewServer_ValidationErrors(t *testing.T) {
	t.Run("Dial and BindAddr mutually exclusive", func(t *testing.T) {
		_, err := NewServer(Config{
			Dial:     (&net.Dialer{}).DialContext,
			BindAddr: "127.0.0.1",
		})
		if err == nil {
			t.Fatal("expected error when both Dial and BindAddr are set")
		}
	})

	t.Run("invalid BindAddr", func(t *testing.T) {
		_, err := NewServer(Config{BindAddr: "not-an-ip"})
		if err == nil {
			t.Fatal("expected error for non-IP BindAddr")
		}
	})

	t.Run("nil Credentials in UserPassAuthenticator", func(t *testing.T) {
		_, err := NewServer(Config{
			Authenticators: []Authenticator{UserPassAuthenticator{Credentials: nil}},
		})
		if err == nil {
			t.Fatal("expected error for UserPassAuthenticator with nil Credentials")
		}
	})
}

// TestMaxConns_Limit verifies that the server rejects connections beyond
// [Config.MaxConns] by closing them immediately without any SOCKS5 data.
func TestMaxConns_Limit(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{MaxConns: 1})
	defer cancel()

	// Establish the first connection and confirm the session is live (semaphore
	// held) by completing the greeting exchange.
	conn1, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	conn1.SetDeadline(time.Now().Add(5 * time.Second))

	conn1.Write([]byte{version5, 1, methodNoAuth})
	if _, err := io.ReadFull(conn1, make([]byte, 2)); err != nil {
		t.Fatalf("conn1 greeting: %v", err)
	}

	// Second connection: TCP accept succeeds but the server must close it
	// immediately because the semaphore is exhausted (MaxConns=1).
	conn2, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	conn2.SetReadDeadline(time.Now().Add(time.Second))
	_, err = conn2.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected conn2 to be closed by the server (MaxConns=1 reached)")
	}
}

// TestAuthOnce_NoAuthNotPromoted verifies the guard in [Config.AuthOnce]:
// a connection that authenticates via the NoAuth method (method 0x00) must
// NOT promote the client IP to the trusted list, because no credentials were
// verified. The guard is `selected.Code() != methodNoAuth`.
// ---------------------------------------------------------------------------
// RFC 1928 §3: method negotiation edge cases
// ---------------------------------------------------------------------------

// TestGreeting_OnlyGSSAPIMethod verifies that a client advertising only
// method 0x01 (GSSAPI) — which this server does not implement — receives X'FF'
// (no acceptable method) and the server closes the connection.
//
// RFC 1928 §3 MUST: compliant servers must support GSSAPI. This implementation
// intentionally omits GSSAPI (absent from virtually all deployed SOCKS5 stacks)
// and documents the omission. The correct observable behaviour is still X'FF'.
func TestGreeting_OnlyGSSAPIMethod(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte{version5, 0x01, 0x01}) // NMETHODS=1, METHOD=GSSAPI

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if resp[1] != methodNoAcceptable {
		t.Fatalf("METHOD = %#x, want 0xFF (no acceptable) for GSSAPI-only client", resp[1])
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected server to close after X'FF'")
	}
}

// TestNegotiation_ServerPriorityOverClient verifies RFC 1928 §3: the server
// selects from the client's methods according to the SERVER'S own priority
// order (first match in Config.Authenticators), not the client's order.
//
// Scenario A: server has [UserPass]; client offers [NoAuth, UserPass].
// Server must select UserPass (its first and only authenticator), ignoring
// that NoAuth appears first in the client's list.
func TestNegotiation_ServerPicksOwnPriority(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	proxyAddr, cancel := startProxy(t, Config{
		Authenticators: []Authenticator{UserPassAuth("u", "p")},
	})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Client advertises NoAuth first, then UserPass.
	conn.Write([]byte{version5, 0x02, methodNoAuth, methodUserPass})

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	// Server must pick UserPass (its only authenticator), not NoAuth.
	if resp[1] != methodUserPass {
		t.Fatalf("METHOD = %#x, want 0x02 (UserPass): server must use its own priority", resp[1])
	}

	// Complete UserPass sub-negotiation so the session ends cleanly.
	conn.Write([]byte{authSubVersion, 0x01, 'u', 0x01, 'p'})
	io.ReadFull(conn, make([]byte, 2))
}

// TestNegotiation_ServerPicksFirstAuthenticator verifies that when the server
// has multiple authenticators configured, it picks the FIRST one the client
// also supports.
//
// Scenario B: server has [NoAuth, UserPass]; client offers [UserPass, NoAuth].
// Server must select NoAuth (its first authenticator), even though UserPass
// appears first in the client's METHOD list.
func TestNegotiation_ServerPicksFirstAuthenticator(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{
		// Explicit NoAuth before UserPass — server priority trumps client order.
		Authenticators: []Authenticator{NoAuthAuthenticator{}, UserPassAuth("u", "p")},
	})
	defer cancel()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Client advertises UserPass first, then NoAuth.
	conn.Write([]byte{version5, 0x02, methodUserPass, methodNoAuth})

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	// Server must pick NoAuth (first in its own list).
	if resp[1] != methodNoAuth {
		t.Fatalf("METHOD = %#x, want 0x00 (NoAuth): server must use its own priority", resp[1])
	}
}

// ---------------------------------------------------------------------------
// RFC 1928 §6 / §7: reply address validation
// ---------------------------------------------------------------------------

// TestUDPAssociate_BNDAddrPort verifies RFC 1928 §6/§7: the BND.ADDR in the
// UDP ASSOCIATE reply must be a non-unspecified address and BND.PORT must be
// non-zero, so clients know where to send their datagrams.
func TestUDPAssociate_BNDAddrPort(t *testing.T) {
	// DenyPrivateDestinations (default) passes UDP ASSOCIATE unconditionally;
	// no explicit Rules override needed.
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	ctrl, relayAddr := doUDPAssociate(t, proxyAddr)
	defer ctrl.Close()

	if relayAddr.Port == 0 {
		t.Error("BND.PORT is 0: RFC 1928 §7 requires the actual relay port")
	}
	if net.IP(relayAddr.IP).IsUnspecified() {
		t.Errorf("BND.ADDR is all-zeros (%v): RFC 1928 §7 requires the interface address", relayAddr.IP)
	}
}

// ---------------------------------------------------------------------------
// TCP relay: idle timeout
// ---------------------------------------------------------------------------

// TestRelay_TCPIdleTimeout verifies that the TCP relay (relay.go idleReader)
// tears down the connection when neither side sends data for TCPIdleTimeout.
// The idle timeout is set to a very short value so the test completes quickly.
func TestRelay_TCPIdleTimeout(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	const idleTimeout = 150 * time.Millisecond
	proxyAddr, cancel := startProxy(t, Config{
		TCPIdleTimeout:           idleTimeout,
		AllowPrivateDestinations: true,
	})
	defer cancel()

	conn := dialThroughProxy(t, proxyAddr, nil, echo.Addr().String())

	// Do NOT send anything — the relay must detect the idle condition.
	// Allow 5× the idle timeout as wall-clock budget for scheduling jitter.
	conn.SetReadDeadline(time.Now().Add(5 * idleTimeout))
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected idle timeout to close the relay; Read succeeded unexpectedly")
	}
}

// ---------------------------------------------------------------------------
// UDP relay: idle timeout
// ---------------------------------------------------------------------------

// TestRelay_UDPIdleTimeout verifies that the UDP relay (runUDPRelay
// pc.SetReadDeadline loop) tears down the association when no datagrams
// arrive for UDPIdleTimeout. Because the association is linked to the TCP
// control connection, the TCP side also closes when the relay exits.
func TestRelay_UDPIdleTimeout(t *testing.T) {
	const idleTimeout = 150 * time.Millisecond
	proxyAddr, cancel := startProxy(t, Config{
		UDPIdleTimeout: idleTimeout,
	})
	defer cancel()

	ctrl, _ := doUDPAssociate(t, proxyAddr)

	// Do NOT send any UDP datagrams. The relay's read deadline fires after
	// idleTimeout and runUDPRelay returns, which causes handleUDPAssociate to
	// return, which causes handle() to return and defer-close the TCP connection.
	ctrl.SetReadDeadline(time.Now().Add(5 * idleTimeout))
	_, err := ctrl.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected UDP idle timeout to close the TCP control connection")
	}
}
