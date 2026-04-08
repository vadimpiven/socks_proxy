// SPDX-License-Identifier: Apache-2.0 OR MIT

// rules.go retains the protocol-level types [AddrSpec] and [Command].
// The rule-set system was removed in favour of the single
// [Config.AllowPrivateDestinations] flag: the only meaningful policy
// distinction for a SOCKS5 proxy is whether private/internal destinations
// are reachable, which is a deployment characteristic, not per-request logic.
package socks5

import (
	"net"
	"net/netip"
	"strconv"
)

// AddrSpec is a SOCKS5 network destination: a literal IP address or a domain
// name, plus a port. Exactly one of IP and Domain is set.
//
// IP destinations always use plain IPv4 or IPv6 — IPv4-mapped IPv6
// (::ffff:a.b.c.d) is normalised to plain IPv4 by the parser.
type AddrSpec struct {
	// IP is set for literal-IP destinations. Zero (not IsValid) when Domain is set.
	IP netip.Addr
	// Domain is set for DOMAINNAME destinations. Empty when IP is set.
	Domain string
	// Port is the destination TCP or UDP port.
	Port uint16
}

// String returns a "host:port" string suitable for net.Dial.
func (a AddrSpec) String() string {
	if a.Domain != "" {
		return net.JoinHostPort(a.Domain, strconv.Itoa(int(a.Port)))
	}
	return netip.AddrPortFrom(a.IP, a.Port).String()
}

// AddrPort returns the netip.AddrPort for IP destinations, or the zero value
// for domain destinations (IP not yet resolved).
func (a AddrSpec) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(a.IP, a.Port)
}

// Command is a SOCKS5 request command (RFC 1928 §4).
type Command byte

const (
	CommandConnect      Command = 0x01
	CommandBind         Command = 0x02 // not implemented; rejected with reply 0x07
	CommandUDPAssociate Command = 0x03
)
