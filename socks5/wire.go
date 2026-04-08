// SPDX-License-Identifier: Apache-2.0 OR MIT

// wire.go contains SOCKS5 wire-protocol constants and the unexported encoding
// and decoding functions used by session.go and udp.go. All symbols here are
// unexported; normal use of the package does not require reading this file.
package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
)

// version5 is the only SOCKS protocol version this server accepts (RFC 1928 §3).
const version5 byte = 0x05

// Authentication method codes (RFC 1928 §3).
const (
	methodNoAuth       byte = 0x00
	methodUserPass     byte = 0x02
	methodNoAcceptable byte = 0xFF
)

// Username/password sub-negotiation constants (RFC 1929 §2).
const (
	authSubVersion byte = 0x01
	authSuccess    byte = 0x00
	authFailure    byte = 0x01
)

// Address type bytes (RFC 1928 §5).
const (
	addrTypeIPv4   byte = 0x01
	addrTypeDomain byte = 0x03
	addrTypeIPv6   byte = 0x04
)

// Reply codes (RFC 1928 §6).
const (
	replySuccess          byte = 0x00
	replyGeneralFailure   byte = 0x01
	replyNotAllowed       byte = 0x02
	replyNetUnreachable   byte = 0x03
	replyHostUnreachable  byte = 0x04
	replyConnRefused      byte = 0x05
	replyCmdNotSupported  byte = 0x07
	replyAddrNotSupported byte = 0x08
)

var (
	errUnsupportedAddrType = errors.New("unsupported address type")
	errEmptyDomainName     = errors.New("empty domain name")
)

// readAddr reads ATYP + address + port from the wire (RFC 1928 §4/§5) and
// returns the destination as an AddrSpec. IPv4-mapped IPv6 is normalised to
// plain IPv4.
func readAddr(r io.Reader) (AddrSpec, error) {
	var atype [1]byte
	if _, err := io.ReadFull(r, atype[:]); err != nil {
		return AddrSpec{}, err
	}

	switch atype[0] {
	case addrTypeIPv4:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return AddrSpec{}, err
		}
		port, err := readPort(r)
		if err != nil {
			return AddrSpec{}, err
		}
		return AddrSpec{IP: netip.AddrFrom4(a), Port: port}, nil

	case addrTypeIPv6:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return AddrSpec{}, err
		}
		port, err := readPort(r)
		if err != nil {
			return AddrSpec{}, err
		}
		return AddrSpec{IP: netip.AddrFrom16(a).Unmap(), Port: port}, nil

	case addrTypeDomain:
		var dlen [1]byte
		if _, err := io.ReadFull(r, dlen[:]); err != nil {
			return AddrSpec{}, err
		}
		if dlen[0] == 0 {
			return AddrSpec{}, errEmptyDomainName
		}
		domain := make([]byte, dlen[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return AddrSpec{}, err
		}
		port, err := readPort(r)
		if err != nil {
			return AddrSpec{}, err
		}
		return AddrSpec{Domain: string(domain), Port: port}, nil

	default:
		return AddrSpec{}, fmt.Errorf("%w: %#x", errUnsupportedAddrType, atype[0])
	}
}

func readPort(r io.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// parseAddrFromBytes parses ATYP + address + port from b and returns the
// AddrSpec and the number of bytes consumed. Used by the UDP relay path to
// avoid allocating a bytes.Reader for each incoming datagram.
func parseAddrFromBytes(b []byte) (AddrSpec, int, error) {
	if len(b) == 0 {
		return AddrSpec{}, 0, io.ErrUnexpectedEOF
	}
	switch b[0] {
	case addrTypeIPv4:
		if len(b) < 1+4+2 {
			return AddrSpec{}, 0, io.ErrUnexpectedEOF
		}
		ip := netip.AddrFrom4([4]byte(b[1:5]))
		port := binary.BigEndian.Uint16(b[5:7])
		return AddrSpec{IP: ip, Port: port}, 7, nil

	case addrTypeIPv6:
		if len(b) < 1+16+2 {
			return AddrSpec{}, 0, io.ErrUnexpectedEOF
		}
		ip := netip.AddrFrom16([16]byte(b[1:17])).Unmap()
		port := binary.BigEndian.Uint16(b[17:19])
		return AddrSpec{IP: ip, Port: port}, 19, nil

	case addrTypeDomain:
		if len(b) < 2 {
			return AddrSpec{}, 0, io.ErrUnexpectedEOF
		}
		dlen := int(b[1])
		if dlen == 0 {
			return AddrSpec{}, 0, errEmptyDomainName
		}
		end := 2 + dlen + 2
		if len(b) < end {
			return AddrSpec{}, 0, io.ErrUnexpectedEOF
		}
		domain := string(b[2 : 2+dlen])
		port := binary.BigEndian.Uint16(b[2+dlen : end])
		return AddrSpec{Domain: domain, Port: port}, end, nil

	default:
		return AddrSpec{}, 0, fmt.Errorf("%w: %#x", errUnsupportedAddrType, b[0])
	}
}

// appendAddr appends the ATYP + address wire encoding of spec to buf.
// A zero AddrSpec (IP and Domain both unset) encodes as IPv4 0.0.0.0, which
// is the conventional encoding for error replies (RFC 1928 §6).
func appendAddr(buf []byte, spec AddrSpec) []byte {
	switch {
	case spec.Domain != "":
		buf = append(buf, addrTypeDomain, byte(len(spec.Domain)))
		buf = append(buf, spec.Domain...)
	case spec.IP.Is4():
		a := spec.IP.As4()
		buf = append(buf, addrTypeIPv4)
		buf = append(buf, a[:]...)
	case spec.IP.Is6():
		a := spec.IP.As16()
		buf = append(buf, addrTypeIPv6)
		buf = append(buf, a[:]...)
	default:
		buf = append(buf, addrTypeIPv4, 0, 0, 0, 0)
	}
	return buf
}

// writeReply sends a SOCKS5 reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT.
// A zero AddrSpec encodes as 0.0.0.0:0 (used for all error replies).
func writeReply(w io.Writer, code byte, bound AddrSpec) error {
	buf := make([]byte, 0, 22) // max: 4 header + 16 IPv6 + 2 port
	buf = append(buf, version5, code, 0x00)
	buf = appendAddr(buf, bound)
	buf = append(buf, byte(bound.Port>>8), byte(bound.Port&0xff))
	_, err := w.Write(buf)
	return err
}

// appendUDPResponse writes a SOCKS5 UDP response header (RFC 1928 §7) followed
// by payload into dst and returns the number of bytes written. dst must have
// length of at least 22 + len(payload). Used by the relay loop to avoid a
// per-packet heap allocation.
//
// Header layout: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2) | DATA
//
// Note: the previous implementation used append(dst[:3], ...) relying on
// append staying in the same backing array when cap is large enough. That
// trick is valid but brittle — any change to dst's capacity breaks it
// silently. Direct index writes are explicit and capacity-independent.
func appendUDPResponse(dst []byte, from netip.AddrPort, payload []byte) int {
	dst[0], dst[1], dst[2] = 0, 0, 0 // RSV RSV FRAG
	n := 3

	addr := from.Addr().Unmap()
	switch {
	case addr.Is4():
		a := addr.As4()
		dst[n] = addrTypeIPv4
		n++
		copy(dst[n:], a[:])
		n += 4
	case addr.Is6():
		a := addr.As16()
		dst[n] = addrTypeIPv6
		n++
		copy(dst[n:], a[:])
		n += 16
	default:
		// Zero or invalid address: encode as IPv4 0.0.0.0, matching the
		// appendAddr default case and RFC 1928 §6 error-reply convention.
		dst[n] = addrTypeIPv4
		n++
		dst[n], dst[n+1], dst[n+2], dst[n+3] = 0, 0, 0, 0
		n += 4
	}

	port := from.Port()
	dst[n] = byte(port >> 8)
	dst[n+1] = byte(port)
	n += 2

	copy(dst[n:], payload)
	return n + len(payload)
}

// replyFromError maps a Go network error to the closest SOCKS5 reply code
// (RFC 1928 §6).
//
// Reply 0x06 (TTL exceeded) is reserved for ICMP "time exceeded" and must not
// be used for dial deadlines. A dial deadline or ETIMEDOUT means the host did
// not respond, which maps to replyHostUnreachable (0x04). EHOSTUNREACH covers
// both ICMP host-unreachable and TTL-exceeded because the kernel exposes both
// as the same errno.
func replyFromError(err error) byte {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Timeout() {
		return replyHostUnreachable
	}
	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		switch {
		case errors.Is(sysErr.Err, syscall.ECONNREFUSED):
			return replyConnRefused
		case errors.Is(sysErr.Err, syscall.ETIMEDOUT):
			return replyHostUnreachable
		case errors.Is(sysErr.Err, syscall.ENETUNREACH):
			return replyNetUnreachable
		case errors.Is(sysErr.Err, syscall.EHOSTUNREACH):
			return replyHostUnreachable
		}
	}
	return replyGeneralFailure
}
