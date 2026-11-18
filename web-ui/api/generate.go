package api

import (
	"crypto/rand"
	"encoding/binary"
)

// The draws behind every generated AmneziaWG 3.1 parameter set: one copy for
// the create form, the backend and the per-client variation.

// GenerateObfuscation rolls a full AmneziaWG 3.1 parameter set that passes
// Validate at the given MTU, every number a fresh draw from the system's
// cryptographic source. The fixed set it replaces - Jmin/Jmax 8/80, headers
// 1/2/3/4, one shared padding - was identical on every deployment: one
// observer who has seen one tunnel has seen all of them. MTU and
// HeaderProtectionKey belong to the caller. sharedPadding keeps "one value
// for all four" for the advanced form's deliberate choice; the default is
// four independent draws, since identical paddings make the four message
// types one recognisable size.
func GenerateObfuscation(mtu int, sharedPadding bool) *ObfuscationParams {
	s1, s2, s3, s4 := drawPaddings(mtu, sharedPadding)
	jc, jmin, jmax := drawJunk(mtu)
	h1, h2, h3, h4 := drawHeaders()

	return &ObfuscationParams{
		Jc:             jc,
		Jmin:           jmin,
		Jmax:           jmax,
		S1:             s1,
		S2:             s2,
		S3:             s3,
		S4:             s4,
		H1:             h1,
		H2:             h2,
		H3:             h3,
		H4:             h4,
		RandomTrailers: true,
		DisableCookies: true,
	}
}

// VaryForClient derives the parameter set one client is issued from its
// server's: the junk train is sender-scope and redrawn per client (with its
// own I1-I5 chain from GenerateISettings), while everything the receiver
// compares - H1-H4, S1-S4, the header protection key, MTU, the 3.1 switches
// and the timing knobs - stays exactly the server's. nil in, nil out.
func VaryForClient(server *ObfuscationParams, mtu int) *ObfuscationParams {
	if server == nil {
		return nil
	}
	p := *server
	p.Jc, p.Jmin, p.Jmax = drawJunk(mtu)
	return &p
}

// junkIntensities are the Jmin and Jmax windows of the low, medium and high
// junk trains - far apart, because a length hovering around one number is
// as recognisable as a fixed one.
var junkIntensities = [3][4]int{
	{64, 256, 256, 512},
	{128, 512, 512, 1024},
	{256, 768, 768, 1280},
}

// drawJunk rolls Jc from a level that reads like ordinary traffic, jittered
// by one, and the window from one intensity; Jmax is pushed clear when the
// draws land too close to tell a junk packet from a real one. The bounded
// redraw is for an MTU outside the legal range, which Validate refuses.
func drawJunk(mtu int) (jc, jmin, jmax int) {
	levels := [...]int{3, 5, 7, 10}
	jc = min(max(levels[randInt(0, len(levels)-1)]+randInt(-1, 1), 1), 15)

	for range 32 {
		window := junkIntensities[randInt(0, len(junkIntensities)-1)]
		jmin = randInt(window[0], window[1])
		jmax = randInt(window[2], window[3])
		if jmax <= jmin+64 {
			jmax = jmin + 64 + randInt(64, 256)
		}
		if jmin >= 1 && jmax <= mtu {
			return jc, jmin, jmax
		}
	}
	return jc, 1, max(2, mtu)
}

// The per-message-type padding windows: S1/S2 ride the handshake packets,
// S3/S4 the cookie reply and every transport packet, where a big padding
// would push a full-size packet over the path MTU.
const (
	maxPaddingS1S2 = 150
	maxPaddingS3   = 64
	maxPaddingS4   = 32
)

// paddedLengths are the four on-the-wire message sizes: WireGuard's
// initiation (148), response (92) and cookie reply (64) and the smallest
// transport packet (32), each with its padding on top.
func paddedLengths(s1, s2, s3, s4 int) [4]int {
	return [4]int{s1 + 148, s2 + 92, s3 + 64, s4 + 32}
}

// drawPaddings rolls S1-S4 as four independent draws - or the one shared
// value the advanced form offers - and always returns a set Validate accepts
// at the given MTU. Two message types with the same on-the-wire length give
// the WireGuard message structure away to anyone sorting packets by size:
// the repair walks the offender one step aside and redraws when walking
// cannot settle it.
func drawPaddings(mtu int, sharedPadding bool) (s1, s2, s3, s4 int) {
	s1Max := min(maxPaddingS1S2, mtu-148)
	s2Max := min(maxPaddingS1S2, mtu-92)

	if sharedPadding {
		one := randInt(MinPadding, min(maxPaddingS4, s1Max, s2Max))
		return one, one, one, one
	}

	for range 32 {
		s1, s2 = randInt(MinPadding, s1Max), randInt(MinPadding, s2Max)
		s3, s4 = randInt(MinPadding, maxPaddingS3), randInt(MinPadding, maxPaddingS4)

		ceilings := [4]int{s1Max, s2Max, maxPaddingS3, maxPaddingS4}
		flat := [4]int{s1, s2, s3, s4}
		for range 10 {
			j, clash := collidingPair(flat)
			if !clash {
				return flat[0], flat[1], flat[2], flat[3]
			}
			flat[j] = stepAside(flat[j], ceilings[j])
		}
	}
	return MinPadding, MinPadding + 1, MinPadding + 2, MinPadding + 3
}

// collidingPair finds the later of two message types whose on-the-wire
// lengths meet, so the repair can step that one aside.
func collidingPair(s [4]int) (j int, ok bool) {
	lengths := paddedLengths(s[0], s[1], s[2], s[3])
	for i := range lengths {
		for j := i + 1; j < len(lengths); j++ {
			if lengths[i] == lengths[j] {
				return j, true
			}
		}
	}
	return 0, false
}

// stepAside moves a padding one step away from a collision, downward at the
// top of its window so it never walks out of the range Validate enforces.
func stepAside(value, ceiling int) int {
	if value >= ceiling {
		return max(MinPadding, value-1)
	}
	return value + 1
}

// headerZones cannot overlap - so the four headers are always distinct -
// and stay clear of 1-4, the plain WireGuard message types an observer reads
// as "not obfuscated at all". Narrow on purpose: this app models one value
// per header, and with RandomTrailers on a range would silently cost packets
// the receiver drops.
var headerZones = [4][2]int{
	{100000000, 900000000},
	{1200000000, 2000000000},
	{2400000000, 3200000000},
	{3600000000, 4000000000},
}

// drawHeaders rolls H1-H4, one value from each zone.
func drawHeaders() (int, int, int, int) {
	var h [4]int
	for i, zone := range headerZones {
		h[i] = min(zone[0]+randInt(0, zone[1]-zone[0]), MaxHeader)
	}
	return h[0], h[1], h[2], h[3]
}

// randInt is a uniform draw in [lo, hi] from the cryptographic source;
// rejection sampling keeps it uniform, which a plain modulo would not. A
// source failure panics like awg.RandomKey: predictable values would defeat
// the generator.
func randInt(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	span := uint64(hi-lo) + 1
	limit := ^uint64(0) - ^uint64(0)%span
	for {
		var buf [8]byte
		mustRandom(buf[:])
		if v := binary.LittleEndian.Uint64(buf[:]); v < limit {
			return lo + int(v%span)
		}
	}
}

// randBytes is n bytes baked into a packet at generation time.
func randBytes(n int) []byte {
	b := make([]byte, n)
	mustRandom(b)
	return b
}

// randText is n characters of an alphabet, for the fields a protocol
// constrains to hex digits or the like.
func randText(alphabet string, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[randInt(0, len(alphabet)-1)]
	}
	return b
}

func mustRandom(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
}
