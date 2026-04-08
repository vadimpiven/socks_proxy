// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// Happy-path parsing (IPv4, IPv6, domain, empty payload) is covered by
// TestUDPHeaderRoundtrip and the integration tests. The cases below exercise
// RFC-mandated drop conditions and normalisation that cannot be triggered
// through a normal client.

func TestParseUDPHeader_TooShort(t *testing.T) {
	_, _, err := parseUDPHeader([]byte{0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for datagram shorter than minimum header")
	}
}

// TestParseUDPHeader_NonZeroRSV verifies that datagrams with a non-zero RSV
// field are rejected. RFC 1928 §7 specifies RSV = X'0000'.
func TestParseUDPHeader_NonZeroRSV(t *testing.T) {
	b := []byte{0x00, 0x01, 0x00, addrTypeIPv4, 1, 2, 3, 4, 0x00, 0x50}
	_, _, err := parseUDPHeader(b)
	if err == nil {
		t.Fatal("expected error for non-zero RSV in UDP header")
	}
}

// TestParseUDPHeader_FragmentedDropped verifies that datagrams with FRAG != 0
// are rejected. RFC 1928 §7: "An implementation that does not support
// fragmentation MUST drop any datagram whose FRAG field is other than X'00'."
func TestParseUDPHeader_FragmentedDropped(t *testing.T) {
	b := []byte{0x00, 0x00, 0x01, addrTypeIPv4, 1, 2, 3, 4, 0x00, 0x50}
	_, _, err := parseUDPHeader(b)
	if err == nil {
		t.Fatal("expected error for fragmented UDP datagram (FRAG != 0)")
	}
}

// TestAppendUDPResponse_IPv4MappedNormalised verifies that the response header
// for an IPv4-mapped IPv6 source (::ffff:a.b.c.d) uses ATYP=0x01 (IPv4).
// Clients that don't handle IPv6 can parse the source address correctly.
func TestAppendUDPResponse_IPv4MappedNormalised(t *testing.T) {
	from := netip.MustParseAddrPort("[::ffff:192.0.2.1]:9")
	var dst [udpResponseBufSize]byte
	appendUDPResponse(dst[:], from, nil)
	if dst[3] != addrTypeIPv4 {
		t.Fatalf("ATYP = %#x, want 0x01 (IPv4) for IPv4-mapped source", dst[3])
	}
}

// TestAppendUDPResponse_ZeroAddr verifies that an invalid (zero) netip.AddrPort
// produces ATYP=0x01 (IPv4) with address 0.0.0.0, matching the appendAddr
// default case and the RFC 1928 §6 error-reply convention. This exercises the
// default branch added by the appendUDPResponse refactor.
func TestAppendUDPResponse_ZeroAddr(t *testing.T) {
	var from netip.AddrPort // zero value: invalid addr, port 0
	var dst [udpResponseBufSize]byte
	n := appendUDPResponse(dst[:], from, []byte("data"))

	if dst[3] != addrTypeIPv4 {
		t.Fatalf("ATYP = %#x, want 0x01 (IPv4) for zero AddrPort", dst[3])
	}
	// Bytes 4-7: IPv4 address, must be 0.0.0.0
	for i := 4; i <= 7; i++ {
		if dst[i] != 0 {
			t.Fatalf("addr byte[%d] = %#x, want 0x00 for zero addr", i, dst[i])
		}
	}
	// Payload must follow immediately after the 10-byte IPv4 header.
	const wantHeaderLen = 3 + 1 + 4 + 2 // RSV(2)+FRAG(1)+ATYP(1)+addr(4)+port(2)
	if n != wantHeaderLen+4 {
		t.Fatalf("total len = %d, want %d", n, wantHeaderLen+4)
	}
	if string(dst[wantHeaderLen:n]) != "data" {
		t.Fatalf("payload = %q, want %q", dst[wantHeaderLen:n], "data")
	}
}

// TestUDPHeaderRoundtrip verifies that appendUDPResponse and parseUDPHeader
// are inverses of each other across all address families.
func TestUDPHeaderRoundtrip(t *testing.T) {
	cases := []struct {
		from    netip.AddrPort
		payload string
	}{
		{netip.MustParseAddrPort("192.168.1.1:5000"), "ipv4 payload"},
		{netip.MustParseAddrPort("[2001:db8::1]:443"), "ipv6 payload"},
	}
	for _, tc := range cases {
		dst := make([]byte, udpResponseBufSize)
		n := appendUDPResponse(dst, tc.from, []byte(tc.payload))
		encoded := dst[:n]

		dest, payload, err := parseUDPHeader(encoded)
		if err != nil {
			t.Fatalf("parseUDPHeader: %v", err)
		}
		if dest.IP != tc.from.Addr() {
			t.Fatalf("IP = %v, want %v", dest.IP, tc.from.Addr())
		}
		if dest.Port != tc.from.Port() {
			t.Fatalf("port = %d, want %d", dest.Port, tc.from.Port())
		}
		if string(payload) != tc.payload {
			t.Fatalf("payload = %q, want %q", payload, tc.payload)
		}
	}
}

// startUDPEchoServer starts a UDP server that echoes every datagram back to
// its sender.
func startUDPEchoServer(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, udpBufSize)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

// doUDPAssociate performs the SOCKS5 TCP handshake and UDP ASSOCIATE request,
// returning the control connection and the relay socket address.
func doUDPAssociate(t *testing.T, proxyAddr string) (ctrl net.Conn, relayAddr *net.UDPAddr) {
	t.Helper()
	ctrl, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ctrl.Write([]byte{version5, 0x01, methodNoAuth})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, resp); err != nil {
		ctrl.Close()
		t.Fatal(err)
	}
	if resp[1] != methodNoAuth {
		ctrl.Close()
		t.Fatalf("method = %#x, want NoAuth", resp[1])
	}

	// RFC 1928 §7: use all-zeros hint when the client UDP address is not known.
	ctrl.Write([]byte{version5, byte(CommandUDPAssociate), 0x00, addrTypeIPv4, 0, 0, 0, 0, 0, 0})

	reply := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, reply); err != nil {
		ctrl.Close()
		t.Fatal(err)
	}
	if reply[1] != replySuccess {
		ctrl.Close()
		t.Fatalf("UDP ASSOCIATE reply = %#x, want 0x00 (success)", reply[1])
	}

	var relayIP net.IP
	var relayPort uint16
	switch reply[3] {
	case addrTypeIPv4:
		b := make([]byte, 6)
		io.ReadFull(ctrl, b)
		relayIP, relayPort = net.IP(b[:4]), binary.BigEndian.Uint16(b[4:6])
	case addrTypeIPv6:
		b := make([]byte, 18)
		io.ReadFull(ctrl, b)
		relayIP, relayPort = net.IP(b[:16]), binary.BigEndian.Uint16(b[16:18])
	default:
		ctrl.Close()
		t.Fatalf("unexpected ATYP in UDP ASSOCIATE reply: %#x", reply[3])
	}
	return ctrl, &net.UDPAddr{IP: relayIP, Port: int(relayPort)}
}

// TestUDPAssociate_EchoRoundtrip is the primary UDP integration test.
// It verifies that the relay forwards a client datagram to the destination,
// encapsulates the reply with a SOCKS5 header, and reports the correct source
// address (RFC 1928 §7).
func TestUDPAssociate_EchoRoundtrip(t *testing.T) {
	echoAddr := startUDPEchoServer(t)
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	ctrl, relayAddr := doUDPAssociate(t, proxyAddr)
	defer ctrl.Close()

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("udp-echo-test")
	echoIP := echoAddr.IP.To4()
	datagram := append([]byte{0x00, 0x00, 0x00, addrTypeIPv4}, echoIP...)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(echoAddr.Port))
	datagram = append(datagram, msg...)

	if _, err := udpConn.WriteTo(datagram, relayAddr); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, udpBufSize)
	n, _, err := udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom relay: %v", err)
	}

	dest, payload, err := parseUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("parseUDPHeader on reply: %v", err)
	}
	if dest.IP.String() != netip.AddrFrom4([4]byte(echoIP)).String() {
		t.Fatalf("reported source IP = %v, want echo server %v", dest.IP, echoIP)
	}
	if dest.Port != uint16(echoAddr.Port) {
		t.Fatalf("reported source port = %d, want %d", dest.Port, echoAddr.Port)
	}
	if string(payload) != string(msg) {
		t.Fatalf("payload = %q, want %q", payload, msg)
	}
}

// TestUDPAssociate_PortChangingRemote verifies RFC 1928 §7: the relay must
// forward replies from remote hosts regardless of source port. This covers
// load balancers and NAT devices that reply from a different port than they
// listen on.
func TestUDPAssociate_PortChangingRemote(t *testing.T) {
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	listenConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listenConn.Close()
	replyConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer replyConn.Close()
	listenAddr := listenConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buf := make([]byte, 1024)
		n, from, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		replyConn.WriteToUDP(buf[:n], from) // reply from a different port
	}()

	ctrl, relayAddr := doUDPAssociate(t, proxyAddr)
	defer ctrl.Close()

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("port-change-test")
	datagram := append([]byte{0x00, 0x00, 0x00, addrTypeIPv4}, listenAddr.IP.To4()...)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(listenAddr.Port))
	datagram = append(datagram, msg...)

	if _, err := udpConn.WriteTo(datagram, relayAddr); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, udpBufSize)
	n, _, err := udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected reply from port-changing remote: %v", err)
	}
	_, payload, err := parseUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("parseUDPHeader: %v", err)
	}
	if string(payload) != string(msg) {
		t.Fatalf("payload = %q, want %q", payload, msg)
	}
}

// fixedIPResolver is a test-only [Resolver] that always returns a pre-set
// address, letting UDP domain tests control resolution without depending on
// system DNS or the address family that "localhost" happens to resolve to.
type fixedIPResolver struct{ addr netip.Addr }

func (r fixedIPResolver) Resolve(_ context.Context, _ string) (netip.Addr, error) {
	return r.addr, nil
}

// TestUDPAssociate_DomainDestination verifies that the UDP relay resolves a
// DOMAINNAME destination (ATYP=0x03) in a client datagram and forwards the
// payload to the resolved address (RFC 1928 §7).
//
// A fixed resolver is used so the test is independent of system DNS and
// address-family selection.
func TestUDPAssociate_DomainDestination(t *testing.T) {
	echoAddr := startUDPEchoServer(t)

	// Use a resolver that always returns 127.0.0.1 so the relay stays on
	// the same IPv4 network as the echo server and the relay socket.
	proxyAddr, cancel := startProxy(t, Config{
		Resolver: fixedIPResolver{netip.MustParseAddr("127.0.0.1")},
	})
	defer cancel()

	ctrl, relayAddr := doUDPAssociate(t, proxyAddr)
	defer ctrl.Close()

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(5 * time.Second))

	msg := []byte("domain-udp-test")
	domain := "echo.test" // arbitrary; fixedIPResolver ignores the name

	// Build a SOCKS5 UDP request with ATYP=0x03 (DOMAINNAME).
	datagram := []byte{0x00, 0x00, 0x00, addrTypeDomain, byte(len(domain))}
	datagram = append(datagram, []byte(domain)...)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(echoAddr.Port))
	datagram = append(datagram, msg...)

	if _, err := udpConn.WriteTo(datagram, relayAddr); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, udpBufSize)
	n, _, err := udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom relay: %v", err)
	}

	_, payload, err := parseUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("parseUDPHeader on reply: %v", err)
	}
	if string(payload) != string(msg) {
		t.Fatalf("payload = %q, want %q", payload, msg)
	}
}

// TestUDPRelay_DropsDatagramFromWrongSourceIP verifies RFC 1928 §7:
// "The UDP relay server MUST … drop any datagrams arriving from any source IP
// address other than the one recorded for the particular association."
//
// runUDPRelay is exercised directly with a clientIP (10.0.0.1) that does not
// match the actual sender (127.0.0.1). In Phase 1, before any client datagram
// is accepted, every inbound datagram whose source IP ≠ clientIP must be
// silently dropped with no reply.
func TestUDPRelay_DropsDatagramFromWrongSourceIP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relay, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	relayAddr := relay.LocalAddr().(*net.UDPAddr)

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	// The relay is told to expect a client from 10.0.0.1; the actual sender is
	// 127.0.0.1, so every datagram must be silently dropped in Phase 1.
	wrongClientIP := netip.MustParseAddr("10.0.0.1")
	go runUDPRelay(ctx, relay, wrongClientIP, DefaultResolver{}, discardLogger(),
		time.Second, 5*time.Second)

	// Send a well-formed SOCKS5 UDP request datagram from the "wrong" source IP.
	datagram := []byte{0x00, 0x00, 0x00, addrTypeIPv4, 127, 0, 0, 1, 0x00, 0x50, 'x'}
	if _, err := sender.WriteTo(datagram, relayAddr); err != nil {
		t.Fatal(err)
	}

	// No response must arrive: the relay drops the datagram because
	// 127.0.0.1 ≠ 10.0.0.1 (clientUDPAddr never set → remote-path → drop).
	sender.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, _, err := sender.ReadFrom(make([]byte, 64))
	if err == nil {
		t.Fatalf("expected datagram to be dropped (wrong source IP), got %d bytes back", n)
	}
}

// TestUDPAssociate_AssociationEndsWithTCP verifies RFC 1928 §7: the UDP
// association must terminate when the TCP control connection closes.
func TestUDPAssociate_AssociationEndsWithTCP(t *testing.T) {
	echoAddr := startUDPEchoServer(t)
	proxyAddr, cancel := startProxy(t, Config{})
	defer cancel()

	ctrl, relayAddr := doUDPAssociate(t, proxyAddr)

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	echoIP := echoAddr.IP.To4()
	datagram := append([]byte{0x00, 0x00, 0x00, addrTypeIPv4}, echoIP...)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(echoAddr.Port))
	datagram = append(datagram, "probe"...)

	// Confirm relay is working before closing the TCP connection.
	udpConn.SetDeadline(time.Now().Add(3 * time.Second))
	udpConn.WriteTo(datagram, relayAddr)
	buf := make([]byte, udpBufSize)
	if _, _, err := udpConn.ReadFrom(buf); err != nil {
		t.Fatalf("relay not working before TCP close: %v", err)
	}

	ctrl.Close()
	time.Sleep(100 * time.Millisecond)

	// Relay must now be torn down.
	udpConn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	udpConn.WriteTo(datagram, relayAddr)
	if n, _, err := udpConn.ReadFrom(buf); err == nil {
		t.Fatalf("expected no reply after TCP close, got %q", buf[:n])
	}
}
