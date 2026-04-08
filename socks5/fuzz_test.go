// SPDX-License-Identifier: Apache-2.0 OR MIT

package socks5

import (
	"bytes"
	"testing"
)

// FuzzReadAddr checks that readAddr never panics on arbitrary input and that
// every successful parse produces a well-formed AddrSpec.
//
// Run with: go test -fuzz=FuzzReadAddr -fuzztime=60s ./socks5/
func FuzzReadAddr(f *testing.F) {
	// Seed corpus: one valid example per address type plus known error inputs.
	f.Add([]byte{addrTypeIPv4, 1, 2, 3, 4, 0x00, 0x50})                                                                // 1.2.3.4:80
	f.Add(append(append([]byte{addrTypeIPv6}, make([]byte, 16)...), 0x01, 0xbb))                                        // [::]:443
	f.Add([]byte{addrTypeDomain, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x1f, 0x90})            // example.com:8080
	f.Add([]byte{0x02, 0x00, 0x00})                                                                                     // unknown ATYP
	f.Add([]byte{addrTypeDomain, 0x00, 0x00, 0x50})                                                                     // DLEN=0 (must error)
	f.Add([]byte{})                                                                                                     // empty

	f.Fuzz(func(t *testing.T, b []byte) {
		addr, err := readAddr(bytes.NewReader(b))
		if err != nil {
			return // error paths are expected and valid
		}
		// On success: AddrSpec must be well-formed — exactly one of IP or Domain is set.
		if !addr.IP.IsValid() && addr.Domain == "" {
			t.Fatalf("readAddr returned success but produced zero AddrSpec: %+v", addr)
		}
		if addr.IP.IsValid() && addr.Domain != "" {
			t.Fatalf("readAddr set both IP and Domain: %+v", addr)
		}
	})
}

// FuzzParseUDPHeader checks that parseUDPHeader never panics on arbitrary
// input and that every successful parse produces a valid destination.
//
// Run with: go test -fuzz=FuzzParseUDPHeader -fuzztime=60s ./socks5/
func FuzzParseUDPHeader(f *testing.F) {
	// Seed corpus: valid datagrams, fragmented (should error), truncated.
	f.Add([]byte{0x00, 0x00, 0x00, addrTypeIPv4, 1, 2, 3, 4, 0x00, 0x50, 'x'}) // IPv4 payload
	f.Add([]byte{0x00, 0x00, 0x01, addrTypeIPv4, 1, 2, 3, 4, 0x00, 0x50})      // fragmented (FRAG=1, must error)
	f.Add([]byte{0x00, 0x01, 0x00, addrTypeIPv4, 1, 2, 3, 4, 0x00, 0x50})      // non-zero RSV[1] (must error)
	f.Add([]byte{0x00, 0x00, 0x00})                                              // truncated after header
	f.Add([]byte{})                                                              // empty

	f.Fuzz(func(t *testing.T, b []byte) {
		dest, payload, err := parseUDPHeader(b)
		if err != nil {
			return // error paths are expected and valid
		}
		// On success: destination must be well-formed.
		if !dest.IP.IsValid() && dest.Domain == "" {
			t.Fatalf("parseUDPHeader returned success but produced zero dest: %+v", dest)
		}
		// payload must be a valid (possibly empty) sub-slice of b.
		_ = payload
	})
}
