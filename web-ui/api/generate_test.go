package api

import (
	"strings"
	"testing"
)

// Both sides generate through this: the create form's simple mode sends what
// it produces without ever showing the user a field to fix, and the backend
// falls back to it for an API caller that sends no parameters. So whatever it
// rolls has to already satisfy Validate, at any MTU a server may have and on
// every roll - a set that is invalid one time in a thousand surfaces as a
// create that fails for no visible reason.
func TestGenerateObfuscationAlwaysValidates(t *testing.T) {
	for _, mtu := range []int{MinMTU, 1330, 1420, MaxMTU} {
		for _, shared := range []bool{false, true} {
			for range 300 {
				p := GenerateObfuscation(mtu, shared)

				if problems := p.Validate(mtu); len(problems) > 0 {
					t.Fatalf("MTU %d, shared %v: generated %+v, rejected by its own validation:\n%s",
						mtu, shared, p, strings.Join(problems, "\n"))
				}
				if !p.RandomTrailers || !p.DisableCookies {
					t.Fatalf("MTU %d: the 3.1 switches should default to on, got %+v", mtu, p)
				}
				// The key is the backend's to generate, from a cryptographic
				// source; the generator must not hand one out.
				if p.HeaderProtectionKey != "" {
					t.Fatalf("MTU %d: generated a header protection key %q", mtu, p.HeaderProtectionKey)
				}

				if shared {
					if !(p.S1 == p.S2 && p.S2 == p.S3 && p.S3 == p.S4) {
						t.Fatalf("MTU %d: shared padding mode produced %d/%d/%d/%d", mtu, p.S1, p.S2, p.S3, p.S4)
					}
					if p.S1 < MinPadding || p.S1 > maxPaddingS4 {
						t.Fatalf("MTU %d: shared padding %d outside [%d, %d]", mtu, p.S1, MinPadding, maxPaddingS4)
					}
				} else {
					for name, value := range map[string]int{"S1": p.S1, "S2": p.S2} {
						if value < MinPadding || value > maxPaddingS1S2 {
							t.Fatalf("MTU %d: %s = %d outside [%d, %d]", mtu, name, value, MinPadding, maxPaddingS1S2)
						}
					}
					if p.S3 < MinPadding || p.S3 > maxPaddingS3 {
						t.Fatalf("MTU %d: S3 = %d outside [%d, %d]", mtu, p.S3, MinPadding, maxPaddingS3)
					}
					if p.S4 < MinPadding || p.S4 > maxPaddingS4 {
						t.Fatalf("MTU %d: S4 = %d outside [%d, %d]", mtu, p.S4, MinPadding, maxPaddingS4)
					}
				}

				if p.Jmin < 64 || p.Jmin > 768 || p.Jmax <= p.Jmin+64 || p.Jmax > mtu {
					t.Fatalf("MTU %d: junk window Jmin %d, Jmax %d is not a valid draw", mtu, p.Jmin, p.Jmax)
				}
			}
		}
	}
}

// Two message types with the same on-the-wire length give the WireGuard
// message structure away to anyone sorting packets by size, so no generated
// set may have two paddings land on the same total.
func TestGeneratedPaddingsHoldTheMessageTypesApart(t *testing.T) {
	for _, mtu := range []int{MinMTU, MaxMTU} {
		for range 2000 {
			s1, s2, s3, s4 := drawPaddings(mtu, false)
			lengths := paddedLengths(s1, s2, s3, s4)
			seen := map[int]bool{}
			for _, n := range lengths {
				if seen[n] {
					t.Fatalf("MTU %d: paddings %d/%d/%d/%d give two message types the length %d",
						mtu, s1, s2, s3, s4, n)
				}
				seen[n] = true
			}
		}
	}
}

// The headers replace the message type field of every packet type. They must
// differ from each other and stay clear of 1/2/3/4 - the plain WireGuard
// message types, which read as "no custom headers" to anyone looking.
func TestHeadersAvoidThePlainWireGuardTypes(t *testing.T) {
	zones := [][2]int{}
	for _, zone := range headerZones {
		zones = append(zones, zone)
	}

	for range 200 {
		h := [4]int{}
		h[0], h[1], h[2], h[3] = drawHeaders()

		seen := map[int]bool{}
		for i, value := range h {
			if value < 1 || value > MaxHeader {
				t.Fatalf("H%d = %d outside [%d, %d]", i+1, value, 1, MaxHeader)
			}
			if seen[value] {
				t.Fatalf("headers %v repeat %d", h, value)
			}
			seen[value] = true
			if value <= 4 {
				t.Fatalf("H%d = %d lands on a plain WireGuard message type", i+1, value)
			}
			if value < zones[i][0] || value > zones[i][1] {
				t.Fatalf("H%d = %d outside its zone [%d, %d]", i+1, value, zones[i][0], zones[i][1])
			}
		}
	}
}

// Two servers - and two clients of one server - must not come out with the
// same parameter set: a fixed shape is the template this generator exists to
// get rid of.
func TestGenerationsAreNotOneTemplate(t *testing.T) {
	first := GenerateObfuscation(MinMTU, false)
	distinct := 0
	for range 12 {
		if *GenerateObfuscation(MinMTU, false) != *first {
			distinct++
		}
	}
	if distinct == 0 {
		t.Fatal("12 generations produced the same parameter set every time")
	}
}

// A client shares everything its server's receiver compares, and varies only
// the junk train its own sender emits.
func TestVaryForClientRedrawsOnlyTheSenderScopeNumbers(t *testing.T) {
	server := GenerateObfuscation(1420, false)
	server.HeaderProtectionKey = "KEY"
	server.MTU = 1420

	client := VaryForClient(server, 1420)
	if client == server {
		t.Fatal("VaryForClient aliased the server's parameter set")
	}
	if client.S1 != server.S1 || client.S2 != server.S2 || client.S3 != server.S3 || client.S4 != server.S4 ||
		client.H1 != server.H1 || client.H2 != server.H2 || client.H3 != server.H3 || client.H4 != server.H4 ||
		client.HeaderProtectionKey != server.HeaderProtectionKey || client.MTU != server.MTU ||
		client.RandomTrailers != server.RandomTrailers || client.DisableCookies != server.DisableCookies {
		t.Fatalf("a receiver-compared field changed: client %+v, server %+v", client, server)
	}
	if problems := client.Validate(1420); len(problems) > 0 {
		t.Fatalf("client draw does not validate: %s", strings.Join(problems, "\n"))
	}
	if VaryForClient(nil, 1420) != nil {
		t.Fatal("a server without obfuscation must stay without it")
	}
}

// The shared-padding mode keeps "one value for all four" available - the
// shape the advanced form offers - and it has to stay legal while it does.
func TestSharedPaddingKeepsOneValueForAllFour(t *testing.T) {
	for range 100 {
		p := GenerateObfuscation(MaxMTU, true)
		if !(p.S1 == p.S2 && p.S2 == p.S3 && p.S3 == p.S4) {
			t.Fatalf("want all four paddings equal, got %d/%d/%d/%d", p.S1, p.S2, p.S3, p.S4)
		}
		if problems := p.Validate(MaxMTU); len(problems) > 0 {
			t.Fatalf("shared padding rejected: %s", strings.Join(problems, "\n"))
		}
	}
}
