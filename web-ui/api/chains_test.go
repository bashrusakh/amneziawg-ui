package api

import (
	"bytes"
	"fmt"
	"maps"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// expand renders a packet template to the bytes it produces at send time,
// with zeros standing in for the random runs and the timestamp: these tests
// walk structure and lengths, which do not depend on the drawn values.
func expand(p packet) []byte {
	var out []byte
	for _, e := range p {
		switch e.kind {
		case tagStatic:
			out = append(out, e.data...)
		case tagStamp:
			out = append(out, 0, 0, 0, 0)
		default:
			out = append(out, make([]byte, e.count)...)
		}
	}
	return out
}

func be16(b []byte) int { return int(b[0])<<8 | int(b[1]) }
func be24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

// quicVarint decodes a QUIC variable-length integer (RFC 9000 §16).
func quicVarint(b []byte) (value, size int) {
	switch b[0] >> 6 {
	case 0:
		return int(b[0]), 1
	case 1:
		return be16(b[:2]) & 0x3fff, 2
	case 2:
		return int(b[0]&0x3f)<<24 | be24(b[1:4]), 4
	default:
		v := 0
		for _, c := range b[1:8] {
			v = v<<8 | int(c)
		}
		return v, 8
	}
}

// A chain is what every client with I-settings enabled is issued, so it must
// pass the same validation the editor and the API enforce on hand-typed
// values, on every draw.
func TestGenerateISettingsProducesAValidChain(t *testing.T) {
	for range 200 {
		chain := GenerateISettings()
		for slot := 1; slot <= 5; slot++ {
			if _, ok := chain[fmt.Sprintf("i%d", slot)]; !ok {
				t.Fatalf("chain is missing i%d: %v", slot, chain)
			}
		}
		if chain["i1"] == "" {
			t.Fatal("I1 is the packet the rest hang off; it must never be empty")
		}
		if problems := ValidateISettings(chain); len(problems) > 0 {
			t.Fatalf("generated chain does not validate: %s", strings.Join(problems, "\n"))
		}
	}
}

// The kernel module configures the device in one netlink message: past the
// budget the interface comes up and the tunnel is dead.
func TestChainsFitTheNetlinkBudget(t *testing.T) {
	for range 500 {
		total := chainBytes(GenerateISettings())
		if total > chainBudget {
			t.Fatalf("chain is %d bytes serialized, budget is %d", total, chainBudget)
		}
	}
}

// Only the five tags amneziawg-go builds packets from may appear: <c> is
// kernel-only and rejected outright, <d>/<ds>/<dz> copy a source buffer an
// I-packet does not have. Text outside tags builds nothing and would only
// confuse a reader of the config.
func TestChainsUseOnlyTagsTheEngineBuildsPacketsFrom(t *testing.T) {
	tags := regexp.MustCompile(`<([^<>]*)>`)
	for range 200 {
		for key, value := range GenerateISettings() {
			if rest := tags.ReplaceAllString(value, ""); rest != "" {
				t.Fatalf("%s: %q carries text outside its tags", key, rest)
			}
			for _, match := range tags.FindAllStringSubmatch(value, -1) {
				fields := strings.Fields(match[1])
				switch fields[0] {
				case "b", "t":
				case "r", "rc", "rd":
					n, err := strconv.Atoi(fields[1])
					if err != nil || n < 1 || n > MaxCPSCount {
						t.Fatalf("%s: run %q must carry 1..%d bytes", key, match[0], MaxCPSCount)
					}
				default:
					t.Fatalf("%s: forbidden or unknown tag %q", key, match[0])
				}
			}
		}
	}
}

// Every length field in a generated packet has to cover the bytes the tags
// expand to at send time, or a parser walks off into what follows. Each
// check parses the expanded packet to its last byte the way the protocol in
// question would.
func TestPacketsParseToTheirLastByte(t *testing.T) {
	for range 50 {
		checkQUIC(t, expand(quicLongPacket(drawRow(), false)), false)
		checkQUIC(t, expand(quicLongPacket(drawRow(), true)), true)
		checkTLS(t, expand(tlsClientHello(drawRow())))
		checkDTLS12(t, expand(dtls12ClientHello(drawRow())))
		checkDTLS13(t, expand(dtls13ClientHello(drawRow())))
		checkDNS(t, expand(dnsQuery()))
		checkSIP(t, expand(sipRegister()))

		for _, msg := range stunChain() {
			checkSTUN(t, expand(msg))
		}
	}
}

// The size table is what the mimicry rests on: a packet that lands outside
// the drawn row's slot for its protocol - like QUIC payloads once did, capped
// to half the target - is itself the signature. Totals are spot-checked per
// row across many draws; the Chromium-family rows land on a multiple of 128
// inside the slot, the rest land inside the slot as drawn.
func TestPacketsHitTheirBrowserRowSizes(t *testing.T) {
	for _, row := range browserRows {
		for range 30 {
			inSlot(t, "QUIC Initial", len(expand(quicLongPacket(row, false))), row.qi)
			inSlot(t, "QUIC 0-RTT", len(expand(quicLongPacket(row, true))), row.q0)
			inSlot(t, "DTLS 1.2", len(expand(dtls12ClientHello(row))), row.dtls)
			inSlot(t, "DTLS 1.3", len(expand(dtls13ClientHello(row))), row.dtls)
			inSlot(t, "Noise_IK", len(expand(noiseIKHandshake(row))), row.nx)

			got := len(expand(tlsClientHello(row)))
			if row.chromium && got%128 != 0 {
				t.Fatalf("Chromium-family TLS ClientHello is %d bytes, want a multiple of 128", got)
			}
			inSlot(t, "TLS ClientHello", got, row.tls)
		}
	}
}

// The table is pinned against the fingerprint source it is transcribed from;
// a cell that drifts from it must fail here.
func TestBrowserRowsMatchTheFingerprintTable(t *testing.T) {
	want := [3]browserRow{
		{ // Chrome / Edge
			qi: sizeRange{1250, 1250}, q0: sizeRange{1250, 1350},
			tls: sizeRange{512, 800}, dtls: sizeRange{1100, 1200},
			nx: sizeRange{1200, 1250}, chromium: true,
		},
		{ // Firefox
			qi: sizeRange{1200, 1252}, q0: sizeRange{1200, 1300},
			tls: sizeRange{512, 700}, dtls: sizeRange{1050, 1200},
			nx: sizeRange{1200, 1250},
		},
		{ // Safari
			qi: sizeRange{1250, 1252}, q0: sizeRange{1200, 1300},
			tls: sizeRange{512, 750}, dtls: sizeRange{1100, 1200},
			nx: sizeRange{1200, 1250},
		},
	}
	if browserRows != want {
		t.Errorf("browserRows = %+v, want the fingerprint table %+v", browserRows, want)
	}
}

func inSlot(t *testing.T, name string, n int, slot sizeRange) {
	t.Helper()
	if n < slot[0] || n > slot[1] {
		t.Fatalf("%s is %d bytes, want the %d..%d slot", name, n, slot[0], slot[1])
	}
}

func checkQUIC(t *testing.T, b []byte, zeroRTT bool) {
	t.Helper()
	pnLen := int(b[0]&3) + 1
	base := 0xc0
	if zeroRTT {
		base = 0xd0
	}
	if int(b[0]&0xfc) != base {
		t.Fatalf("QUIC flags %#02x do not name the %s packet type", b[0], map[bool]string{false: "Initial", true: "0-RTT"}[zeroRTT])
	}
	if !bytes.Equal(b[1:5], []byte{0, 0, 0, 1}) {
		t.Fatalf("QUIC version %x, want 00000001", b[1:5])
	}

	i := 5
	i += 1 + int(b[i]) // DCID
	i += 1 + int(b[i]) // SCID
	if !zeroRTT {
		tokenLen, n := quicVarint(b[i:])
		i += n + tokenLen
	}
	length, n := quicVarint(b[i:])
	i += n
	if length != len(b)-i {
		t.Fatalf("QUIC Length %d covers %d bytes (pnLen %d)", length, len(b)-i, pnLen)
	}
	if length < pnLen+16 {
		t.Fatalf("QUIC Length %d leaves no room for the packet number and AEAD tag", length)
	}
}

func checkTLS(t *testing.T, b []byte) {
	t.Helper()
	if b[0] != 0x16 || b[1] != 0x03 || b[2] != 0x01 {
		t.Fatalf("TLS record header %x", b[:3])
	}
	if recLen := be16(b[3:5]); recLen != len(b)-5 {
		t.Fatalf("TLS record length %d covers %d bytes", recLen, len(b)-5)
	}
	if b[5] != 0x01 {
		t.Fatalf("TLS handshake type %#02x, want client_hello", b[5])
	}
	if hsLen := be24(b[6:9]); hsLen != len(b)-9 {
		t.Fatalf("TLS handshake length %d covers %d bytes", hsLen, len(b)-9)
	}
	if !bytes.Equal(b[9:11], []byte{0x03, 0x03}) {
		t.Fatalf("TLS legacy version %x", b[9:11])
	}
}

// checkDTLSRecord walks the record framing both DTLS profiles keep: type,
// legacy version, epoch, a 48-bit sequence number with its low byte where a
// young session has it, and a record length that covers the rest.
func checkDTLSRecord(t *testing.T, b []byte) []byte {
	t.Helper()
	if b[0] != 0x16 || b[1] != 0xfe || b[2] != 0xfd {
		t.Fatalf("DTLS record header %x", b[:3])
	}
	if be16(b[3:5]) != 0 {
		t.Fatalf("DTLS epoch %x", b[3:5])
	}
	if b[10] > 4 {
		t.Fatalf("DTLS sequence low byte %d, want 0..4", b[10])
	}
	if recLen := be16(b[11:13]); recLen != len(b)-13 {
		t.Fatalf("DTLS record length %d covers %d bytes", recLen, len(b)-13)
	}
	return b[13:]
}

func checkDTLSHandshakeHead(t *testing.T, hs []byte) int {
	t.Helper()
	if hs[0] != 0x01 {
		t.Fatalf("DTLS handshake type %#02x, want client_hello", hs[0])
	}
	bodyLen := be24(hs[1:4])
	if be24(hs[6:9]) != 0 || be24(hs[9:12]) != bodyLen {
		t.Fatalf("DTLS fragment header %x, want an unfragmented message", hs[:12])
	}
	return bodyLen
}

func checkDTLS12(t *testing.T, b []byte) {
	t.Helper()
	hs := checkDTLSRecord(t, b)
	bodyLen := checkDTLSHandshakeHead(t, hs)
	if bodyLen != 34 {
		t.Fatalf("DTLS 1.2 body length %d, want the version and 32-byte random", bodyLen)
	}
	if !bytes.Equal(hs[12:14], []byte{0xfe, 0xfd}) {
		t.Fatalf("DTLS 1.2 client version %x", hs[12:14])
	}
}

func checkDTLS13(t *testing.T, b []byte) {
	t.Helper()
	hs := checkDTLSRecord(t, b)
	if bodyLen := checkDTLSHandshakeHead(t, hs); bodyLen != len(hs)-12 {
		t.Fatalf("DTLS 1.3 body length %d covers %d bytes", bodyLen, len(hs)-12)
	}

	body := hs[12:]
	i := 2 + 32 + 2 + 8 + 2 // version, random, session+cookie, suites, compression
	extTotal := be16(body[i : i+2])
	i += 2
	if extTotal != len(body)-i {
		t.Fatalf("DTLS 1.3 extensions length %d covers %d bytes", extTotal, len(body)-i)
	}
	if be16(body[i:i+2]) != 0x002b || be16(body[i+2:i+4]) != 3 {
		t.Fatalf("DTLS 1.3 supported_versions %x", body[i:i+7])
	}
	i += 7

	grease := body[i]
	if grease != body[i+1] || grease&0x0f != 0x0a {
		t.Fatalf("DTLS 1.3 GREASE extension type %x, want 0xNANA", body[i:i+2])
	}
	if greaseLen := be16(body[i+2 : i+4]); greaseLen != len(body)-i-4 {
		t.Fatalf("DTLS 1.3 GREASE length %d swallows %d bytes", greaseLen, len(body)-i-4)
	}
}

func checkDNS(t *testing.T, b []byte) {
	t.Helper()
	if len(b) > 512 {
		t.Fatalf("DNS query is %d bytes", len(b))
	}
	arCount := be16(b[10:12])

	i := 12 // QNAME
	for {
		label := int(b[i])
		i++
		if label == 0 {
			break
		}
		i += label
	}
	i += 4 // QTYPE and QCLASS

	if arCount == 0 {
		if i != len(b) {
			t.Fatalf("unpadded DNS query holds %d trailing bytes", len(b)-i)
		}
		return
	}
	if b[i] != 0 || be16(b[i+1:i+3]) != 0x0029 {
		t.Fatalf("DNS additional record %x, want an OPT RR", b[i:i+3])
	}
	if be16(b[i+3:i+5]) != 1232 {
		t.Fatalf("OPT class %d, want the advertised 1232-byte payload", be16(b[i+3:i+5]))
	}
	rdLen := be16(b[i+9 : i+11])
	i += 11
	if be16(b[i:i+2]) != 0x000c {
		t.Fatalf("OPT option %x, want the padding option", b[i:i+2])
	}
	if optLen := be16(b[i+2 : i+4]); optLen != rdLen-4 {
		t.Fatalf("padding option %d bytes inside a %d-byte RDLENGTH", optLen, rdLen)
	}
	if i+rdLen != len(b) {
		t.Fatalf("OPT record ends %d bytes before the query does", len(b)-i-rdLen)
	}
}

func checkSIP(t *testing.T, b []byte) {
	t.Helper()
	text := string(b)
	sep := strings.Index(text, "\r\n\r\n")
	if sep < 0 {
		t.Fatal("SIP message has no blank line")
	}
	digits := regexp.MustCompile(`Content-Length: (\d+)\r\n`).FindStringSubmatch(text)
	if digits == nil {
		t.Fatal("SIP message has no Content-Length")
	}
	want, _ := strconv.Atoi(digits[1])
	if got := len(b) - sep - 4; got != want {
		t.Fatalf("Content-Length %d covers %d body bytes", want, got)
	}
}

func checkSTUN(t *testing.T, b []byte) {
	t.Helper()
	if length := be16(b[2:4]); length != len(b)-20 {
		t.Fatalf("STUN length %d covers %d attribute bytes", length, len(b)-20)
	}
	if !bytes.Equal(b[4:8], []byte{0x21, 0x12, 0xa4, 0x42}) {
		t.Fatalf("STUN magic cookie %x", b[4:8])
	}
	i := 20
	for i < len(b) {
		valueLen := be16(b[i+2 : i+4])
		i += 4 + valueLen + (4-valueLen%4)%4
	}
	if i != len(b) {
		t.Fatalf("STUN attributes stop %d bytes short of the message", len(b)-i)
	}
}

// Two chains must not come out the same: a chain that repeats across clients
// is the shipped template this generator exists to get rid of.
func TestChainsAreNotOneTemplate(t *testing.T) {
	first := GenerateISettings()
	distinct := 0
	for range 12 {
		if !maps.Equal(GenerateISettings(), first) {
			distinct++
		}
	}
	if distinct == 0 {
		t.Fatal("12 generations produced the same chain every time")
	}
}

// When a chain is over budget, I5 down to I2 give up their packet and then
// drop; I1 - the packet the rest hang off - is never touched.
func TestShrinkToBudgetKeepsI1AndSparesItLast(t *testing.T) {
	chain := ISettings{
		"i1": strings.Repeat("x", 2500),
		"i2": strings.Repeat("x", 300),
		"i3": strings.Repeat("x", 300),
		"i4": strings.Repeat("x", 300),
		"i5": strings.Repeat("x", 300),
	}

	shrinkToBudget(chain)

	if chain["i1"] != strings.Repeat("x", 2500) {
		t.Fatal("I1 must never be touched")
	}
	if chain["i5"] != "" {
		t.Errorf("I5 = %q, want it dropped first", chain["i5"])
	}
	if chain["i4"] != "<r 10>" {
		t.Errorf("I4 = %q, want the small entropy packet that settles the budget", chain["i4"])
	}
	if chain["i2"] != strings.Repeat("x", 300) || chain["i3"] != strings.Repeat("x", 300) {
		t.Error("I2/I3 were touched although the budget settled at I4")
	}
	if total := chainBytes(chain); total > chainBudget {
		t.Errorf("chain is %d bytes after shrinking, budget is %d", total, chainBudget)
	}
}
