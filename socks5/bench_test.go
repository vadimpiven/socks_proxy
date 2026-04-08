// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// BenchmarkRelay measures sustained unidirectional throughput of the
// bidirectional TCP relay (relay.go) using real TCP connections.
//
//	go test -bench=BenchmarkRelay -benchmem -benchtime=5s ./socks5/
func BenchmarkRelay(b *testing.B) {
	const chunkSize = 32 * 1024

	client, proxySide := tcpPair(b)
	remoteProxySide, remote := tcpPair(b)

	go relay(proxySide, remoteProxySide, time.Minute)

	payload := make([]byte, chunkSize)
	sink := make([]byte, chunkSize)

	b.SetBytes(chunkSize)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if _, err := client.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(remote, sink); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHandshake_NoAuth measures the end-to-end cost of a complete SOCKS5
// TCP CONNECT handshake with no authentication: greeting → selection → request
// → reply, plus one byte echo to confirm relay establishment.
//
//	go test -bench=BenchmarkHandshake -benchmem -benchtime=5s ./socks5/
func BenchmarkHandshake_NoAuth(b *testing.B) {
	echo := startEchoServer(b)
	defer echo.Close()
	proxyAddr, cancel := startProxy(b, Config{AllowPrivateDestinations: true})
	defer cancel()

	echoTCP := echo.Addr().(*net.TCPAddr)
	dst := echoTCP.IP.To4()
	dstPort := uint16(echoTCP.Port)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchHandshakeNoAuth(b, proxyAddr, dst, dstPort)
	}
}

// BenchmarkHandshake_UserPass measures the overhead of RFC 1929
// username/password sub-negotiation relative to the no-auth baseline.
//
//	go test -bench=BenchmarkHandshake -benchmem -benchtime=5s ./socks5/
func BenchmarkHandshake_UserPass(b *testing.B) {
	echo := startEchoServer(b)
	defer echo.Close()
	proxyAddr, cancel := startProxy(b, Config{
		Authenticators: []Authenticator{UserPassAuth("bench", "bench")},
	})
	defer cancel()

	echoTCP := echo.Addr().(*net.TCPAddr)
	dst := echoTCP.IP.To4()
	dstPort := uint16(echoTCP.Port)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchHandshakeUserPass(b, proxyAddr, dst, dstPort, "bench", "bench")
	}
}

// benchHandshakeNoAuth performs the full SOCKS5 no-auth handshake manually
// using raw TCP so the benchmark is independent of any third-party SOCKS5
// client library. A one-byte echo confirms the relay is established before
// the connection is closed.
//
// SetLinger(0) is called before Close to emit RST rather than FIN, bypassing
// the TIME_WAIT state that would exhaust the ephemeral port range when many
// thousands of connections are created in a tight loop.
func benchHandshakeNoAuth(b *testing.B, proxyAddr string, dst net.IP, dstPort uint16) {
	b.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		b.Fatal(err)
	}
	defer rstClose(conn)
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// Greeting: VER | NMETHODS | METHOD (no-auth)
	conn.Write([]byte{version5, 1, methodNoAuth}) //nolint:errcheck
	io.ReadFull(conn, make([]byte, 2))            //nolint:errcheck

	// CONNECT request to IPv4 destination.
	req := append([]byte{version5, byte(CommandConnect), 0x00, addrTypeIPv4}, dst...)
	req = binary.BigEndian.AppendUint16(req, dstPort)
	conn.Write(req)                         //nolint:errcheck
	io.ReadFull(conn, make([]byte, 10))     //nolint:errcheck // IPv4 reply

	// One-byte echo confirms the relay is live before we close.
	conn.Write([]byte{'x'})                 //nolint:errcheck
	io.ReadFull(conn, make([]byte, 1))      //nolint:errcheck
}

// benchHandshakeUserPass performs the full SOCKS5 username/password handshake
// manually using raw TCP. See benchHandshakeNoAuth for the SetLinger rationale.
func benchHandshakeUserPass(b *testing.B, proxyAddr string, dst net.IP, dstPort uint16, user, pass string) {
	b.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		b.Fatal(err)
	}
	defer rstClose(conn)
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	// Greeting: VER | NMETHODS | METHOD (username/password)
	conn.Write([]byte{version5, 1, methodUserPass}) //nolint:errcheck
	io.ReadFull(conn, make([]byte, 2))              //nolint:errcheck

	// RFC 1929 sub-negotiation.
	auth := append([]byte{authSubVersion, byte(len(user))}, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	conn.Write(auth)                        //nolint:errcheck
	io.ReadFull(conn, make([]byte, 2))      //nolint:errcheck

	// CONNECT request.
	req := append([]byte{version5, byte(CommandConnect), 0x00, addrTypeIPv4}, dst...)
	req = binary.BigEndian.AppendUint16(req, dstPort)
	conn.Write(req)                         //nolint:errcheck
	io.ReadFull(conn, make([]byte, 10))     //nolint:errcheck

	// One-byte echo confirms relay is live.
	conn.Write([]byte{'x'})                 //nolint:errcheck
	io.ReadFull(conn, make([]byte, 1))      //nolint:errcheck
}

// rstClose sets SO_LINGER(0) and closes conn, causing the kernel to send a
// TCP RST instead of a FIN. This avoids TIME_WAIT, recycling the ephemeral
// port immediately so benchmark loops with thousands of iterations do not
// exhaust the port range.
func rstClose(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetLinger(0) //nolint:errcheck
	}
	conn.Close() //nolint:errcheck
}

// tcpPair returns a connected TCP client/server pair backed by real TCP sockets.
// Both connections and the listener are registered for cleanup with b.Cleanup.
func tcpPair(b *testing.B) (client, server net.Conn) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ln.Close() })
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	server = <-ch
	b.Cleanup(func() { client.Close(); server.Close() })
	return
}
