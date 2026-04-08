// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"net/netip"
	"testing"
)

// TestAddrSpec_String verifies String() for all three address families (IPv4,
// IPv6, domain). The output must be a valid "host:port" argument for net.Dial.
func TestAddrSpec_String(t *testing.T) {
	cases := []struct {
		spec AddrSpec
		want string
	}{
		{AddrSpec{IP: netip.MustParseAddr("1.2.3.4"), Port: 80}, "1.2.3.4:80"},
		{AddrSpec{IP: netip.MustParseAddr("::1"), Port: 443}, "[::1]:443"},
		{AddrSpec{Domain: "example.com", Port: 8080}, "example.com:8080"},
	}
	for _, tc := range cases {
		if got := tc.spec.String(); got != tc.want {
			t.Errorf("AddrSpec(%v).String() = %q, want %q", tc.spec, got, tc.want)
		}
	}
}

// TestAddrSpec_AddrPort verifies that AddrPort() returns the correct
// netip.AddrPort for IP destinations and a zero (invalid) value for domain
// destinations (whose IP is not yet resolved at request time).
func TestAddrSpec_AddrPort(t *testing.T) {
	ip := netip.MustParseAddr("1.2.3.4")
	spec := AddrSpec{IP: ip, Port: 80}
	ap := spec.AddrPort()
	if ap.Addr() != ip {
		t.Errorf("Addr() = %v, want %v", ap.Addr(), ip)
	}
	if ap.Port() != 80 {
		t.Errorf("Port() = %d, want 80", ap.Port())
	}

	// A domain AddrSpec has no IP yet; AddrPort must be invalid.
	domain := AddrSpec{Domain: "example.com", Port: 8080}
	if domain.AddrPort().IsValid() {
		t.Errorf("domain AddrSpec.AddrPort() should be invalid (IP not resolved), got %v",
			domain.AddrPort())
	}
}

// ---------------------------------------------------------------------------
// isPrivateAddr — unit tests for the private-destination guard
// ---------------------------------------------------------------------------

// TestIsPrivateAddr_BlockedRanges verifies that loopback, RFC 1918, link-local,
// and unspecified addresses are classified as private.
func TestIsPrivateAddr_BlockedRanges(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // IPv4 loopback
		"127.0.0.255",     // IPv4 loopback subnet
		"10.0.0.1",        // RFC 1918
		"172.16.0.1",      // RFC 1918
		"192.168.1.1",     // RFC 1918
		"169.254.169.254", // link-local (AWS metadata service)
		"169.254.0.1",     // link-local
		"0.0.0.0",         // unspecified
		"::1",             // IPv6 loopback
		"fc00::1",         // IPv6 ULA
		"fd12:3456::1",    // IPv6 ULA (fd00::/8 ⊂ fc00::/7)
		"fe80::1",         // IPv6 link-local
		"::",              // IPv6 unspecified
	}
	for _, raw := range blocked {
		addr := netip.MustParseAddr(raw)
		if !isPrivateAddr(addr) {
			t.Errorf("isPrivateAddr(%s) = false, want true", raw)
		}
	}
}

// TestIsPrivateAddr_AllowedRanges verifies that public IP addresses are not
// classified as private.
func TestIsPrivateAddr_AllowedRanges(t *testing.T) {
	public := []string{
		"1.1.1.1",
		"8.8.8.8",
		"203.0.113.1",
		"2606:4700:4700::1111",
		"2001:db8::1",
	}
	for _, raw := range public {
		addr := netip.MustParseAddr(raw)
		if isPrivateAddr(addr) {
			t.Errorf("isPrivateAddr(%s) = true, want false", raw)
		}
	}
}

// TestIsPrivateAddr_IPv4MappedIPv6 verifies that an IPv4-mapped IPv6 address
// (::ffff:10.0.0.1) is normalised via Unmap() before the private check.
func TestIsPrivateAddr_IPv4MappedIPv6(t *testing.T) {
	mapped := netip.MustParseAddr("::ffff:10.0.0.1")
	if !isPrivateAddr(mapped) {
		t.Errorf("isPrivateAddr(::ffff:10.0.0.1) = false, want true (RFC 1918 after Unmap)")
	}
}
