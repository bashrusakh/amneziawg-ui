package api

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// The I1-I5 custom signature packets, in the tag language amneziawg-go's
// newObfChain parses. The kernel-only <c> and the buffer tags <d>/<ds>/<dz>
// are never emitted: the first is rejected outright by amneziawg-go, the
// rest copy a source buffer an I-packet does not have. Length fields are
// computed from the expanded sizes - a run counts for the bytes it produces
// at send - so a parser walking the packet finds what the lengths promise.

// chainBudget is the ceiling on one chain's serialized length: the kernel
// module configures the device in one netlink message, and past this the
// interface comes up and the tunnel is dead, silently.
const chainBudget = 3200

// The tag kinds a packet template holds.
const (
	tagStatic = iota
	tagStamp
	tagRandom
	tagLetters
	tagDigits
)

type piece struct {
	kind  int
	data  []byte // tagStatic: the bytes; the run kinds use count
	count int
}

// packet is one signature packet as a template of pieces.
type packet []piece

// wire is the size the packet's pieces expand to at send time.
func (p packet) wire() int {
	size := 0
	for _, e := range p {
		switch e.kind {
		case tagStatic:
			size += len(e.data)
		case tagStamp:
			size += 4
		default:
			size += e.count
		}
	}
	return size
}

// render is the packet as a tag sequence. Runs above MaxCPSCount are split
// across several tags - the grammar takes at most 1000 bytes per run - and
// adjacent static bytes share one tag.
func (p packet) render() string {
	names := map[int]string{tagStamp: "t", tagRandom: "r", tagLetters: "rc", tagDigits: "rd"}

	var sb strings.Builder
	var static []byte
	flush := func() {
		if len(static) > 0 {
			fmt.Fprintf(&sb, "<b 0x%s>", hex.EncodeToString(static))
			static = nil
		}
	}

	for _, e := range p {
		if e.kind == tagStatic {
			static = append(static, e.data...)
			continue
		}
		flush()
		if e.kind == tagStamp {
			sb.WriteString("<t>")
			continue
		}
		for left := e.count; left > 0; {
			chunk := min(left, MaxCPSCount)
			fmt.Fprintf(&sb, "<%s %d>", names[e.kind], chunk)
			left -= chunk
		}
	}
	flush()
	return sb.String()
}

// lit is a run of static bytes, merged with its neighbours at render.
func lit(b []byte) packet {
	if len(b) == 0 {
		return nil
	}
	return packet{{kind: tagStatic, data: b}}
}

func litText(s string) packet { return lit([]byte(s)) }

// drawnText is n characters of the alphabet, baked in at generation time:
// the run tags only draw bytes, letters or digits, so a field the protocol
// constrains to hex digits (a SIP branch, a Call-ID) is drawn here instead.
func drawnText(alphabet string, n int) packet { return lit(randText(alphabet, n)) }

const hexDigits = "0123456789abcdef"

func randRun(kind, n int) packet {
	if n <= 0 {
		return nil
	}
	return packet{{kind: kind, count: n}}
}

func randRaw(n int) packet     { return randRun(tagRandom, n) }
func randLetters(n int) packet { return randRun(tagLetters, n) }
func randDigits(n int) packet  { return randRun(tagDigits, n) }

func join(parts ...packet) packet {
	var out packet
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// The fixed-width integers the protocol layouts are built from.
func u8(v int) packet  { return lit([]byte{byte(v)}) }
func u16(v int) packet { return lit([]byte{byte(v >> 8), byte(v)}) }
func u24(v int) packet {
	return lit([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
}
func u32(v int) packet {
	return lit([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// varint is a QUIC variable-length integer (RFC 9000 §16): the top two bits
// of the first byte say how many bytes follow.
func varint(v int) packet {
	switch {
	case v < 1<<6:
		return u8(v)
	case v < 1<<14:
		return u16(v | 0x4000)
	case v < 1<<30:
		return u32(v | 0x80000000)
	default:
		b := make([]byte, 8)
		b[0] = 0xc0
		for i := 7; i >= 1; i-- {
			b[i] = byte(v)
			v >>= 8
		}
		return lit(b)
	}
}

// GenerateISettings draws one I1-I5 chain: a mimicry profile picked at
// random puts its packet in I1 (some fill more slots), the slots that mimic
// nothing get an entropy chain, and a budget pass keeps the five values
// inside what the kernel accepts at once. Drawn per chain - per client - so
// no two deployments, or two clients, ship the same bytes.
func GenerateISettings() ISettings {
	profile := chainProfiles[randInt(0, len(chainProfiles)-1)]
	slots := profile()

	out := ISettings{}
	for slot := 1; slot <= 5; slot++ {
		key := fmt.Sprintf("i%d", slot)
		switch {
		case slot <= len(slots) && slots[slot-1] != nil:
			out[key] = slots[slot-1].render()
		default:
			out[key] = entropyChain(slot).render()
		}
	}
	shrinkToBudget(out)
	return out
}

// shrinkToBudget trims an over-budget chain from I5 down to I2, each slot
// first giving up its packet for a small one and then dropping. I1 is never
// touched: it is the packet the other four hang off.
func shrinkToBudget(chain ISettings) {
	for slot := 5; slot >= 2 && chainBytes(chain) > chainBudget; slot-- {
		key := fmt.Sprintf("i%d", slot)
		chain[key] = randRaw(10).render()
		if chainBytes(chain) > chainBudget {
			chain[key] = ""
		}
	}
}

func chainBytes(chain ISettings) int {
	total := 0
	for _, v := range chain {
		total += len(v)
	}
	return total
}

// entropyOrders are the orders the pieces of an entropy chain are laid down
// in; the slot picks one, so the four filler packets of a chain do not all
// read the same way.
var entropyOrders = [4][4]int{
	{0, 1, 2, 3},
	{1, 0, 3, 2},
	{2, 3, 0, 1},
	{3, 2, 1, 0},
}

// entropyChain builds the filler packet for a slot that mimics nothing: a
// random run - mostly small, sometimes a big one - letters, digits and
// sometimes a blob of drawn bytes, in the order the slot's permutation of
// entropyOrders says.
func entropyChain(slot int) packet {
	iv := randInt(1, 3)
	base := randInt(4, 20)
	if randInt(1, 10) <= 4 {
		base = randInt(200, 500)
	}

	parts := [4]packet{
		randRaw(min(base*iv, 500)),
		randLetters(randInt(4, 12)),
		randDigits(randInt(4, 8)),
	}
	if randInt(0, 1) == 1 {
		parts[3] = lit(randBytes(randInt(4, 8*iv)))
	}

	var out packet
	for _, idx := range entropyOrders[slot%len(entropyOrders)] {
		out = join(out, parts[idx])
	}
	if out.wire() == 0 {
		return randRaw(10)
	}
	return out
}
