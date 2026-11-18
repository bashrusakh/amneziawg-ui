package api

import (
	"strconv"
	"strings"
)

// The mimicry profiles a signature chain is built from. Each builder
// assembles one packet from the byte layout the named RFC describes, with
// computed lengths and the variable parts left to the run tags: every send
// differs while a parser still finds what the length fields promise.

// sizeRange is a span of UDP payload sizes, inclusive at both ends.
type sizeRange [2]int

// browserRow is one browser's UDP payload sizes per traffic kind - qi for
// QUIC Initial, q0 for 0-RTT, tls for a TLS ClientHello, dtls for DTLS, nx
// for a Noise_IK handshake - and a chain pads toward the row it draws:
// traffic that always lands in one narrow size band is a signature.
// chromium marks the rows whose TLS records land on a multiple of 128
// inside the slot, the way Chromium pads its records.
// The sizes are browser UDP-payload measurements tabulated by the Any Tech
// ARCHITECT project, src/shared/fingerprints.ts (MIT); the values here were
// verified against that table on 2026-11-18.
type browserRow struct {
	qi, q0, tls, dtls, nx sizeRange
	chromium              bool
}

var browserRows = [3]browserRow{
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

// drawRow picks the browser profile one packet is built for.
func drawRow() browserRow { return browserRows[randInt(0, len(browserRows)-1)] }

// maxPacketBytes is the ceiling on one packet: the path MTU minus the UDP/IP
// headers, the number the docs put on an I-packet - past it the packet
// fragments, and the fragmentation is the signature this exists to avoid.
const maxPacketBytes = 1472

// chainProfiles are the profiles a chain draws from, one picked at random
// per chain; each returns the packets filling I1 onwards, and the slots past
// the last one get an entropy chain.
var chainProfiles = []func() []packet{
	func() []packet { return []packet{quicLongPacket(drawRow(), false)} },
	func() []packet { return []packet{tlsClientHello(drawRow())} },
	func() []packet { return []packet{dnsQuery()} },
	func() []packet { return []packet{noiseIKHandshake(drawRow())} },
	func() []packet { return []packet{dtls12ClientHello(drawRow())} },
	stunChain,
	func() []packet { return []packet{sipRegister()} },
	func() []packet { return []packet{quicLongPacket(drawRow(), true)} },
	func() []packet { return []packet{dtls13ClientHello(drawRow())} },
}

// quicLongPacket builds one QUIC long-header packet - Initial (RFC 9000
// §17.2.2) or 0-RTT (§17.2.3, no token field at all). Length covers the
// packet number, payload and AEAD tag; the payload pads the packet out to
// the drawn row's qi/q0 size - a real Initial is 1200 bytes and up, so a QUIC
// packet that always lands short of that is the signature - capped by the
// path MTU.
func quicLongPacket(row browserRow, zeroRTT bool) packet {
	pnLen := randInt(1, 4)
	flags := 0xc0 | (pnLen - 1)
	target := randInt(row.qi[0], row.qi[1])
	if zeroRTT {
		flags = 0xd0 | (pnLen - 1)
		target = randInt(row.q0[0], row.q0[1])
	}
	target = min(target, maxPacketBytes)

	dcidLen := randInt(8, 20)
	scidLen := randInt(0, 20)
	head := join(
		u8(flags),
		lit([]byte{0x00, 0x00, 0x00, 0x01}),
		u8(dcidLen), randRaw(dcidLen),
		u8(scidLen), randRaw(scidLen),
	)

	tokenLen := 0
	if !zeroRTT {
		if randInt(0, 1) == 1 {
			tokenLen = randInt(8, 32)
		}
		head = join(head, varint(tokenLen))
		if tokenLen > 0 {
			head = join(head, randRaw(tokenLen))
		}
	}

	pad := 0
	for range 2 { // the varint's own width depends on the pad it covers
		length := pnLen + pad + 16
		pad = max(target-head.wire()-varint(length).wire()-pnLen-16, 0)
	}
	length := pnLen + pad + 16

	return join(head, varint(length), randRaw(pnLen), randRaw(pad), randRaw(16))
}

// tlsClientHello builds a TLS 1.3 ClientHello record (RFC 8446 §5.1, body
// of §4.1.2): lengths cover everything after them, then the legacy version,
// the 32-byte random, a filler standing in for the session and SNI fields,
// and padding so the record lands on the row's tls size - on one of the
// multiples of 128 inside the slot for the Chromium-family rows, which pad
// their records that way (no row: U[300,550]; every chain draws one).
func tlsClientHello(row browserRow) packet {
	target := randInt(row.tls[0], row.tls[1])
	if row.chromium {
		// Draw one of the multiples of 128 inside the slot rather than
		// rounding a draw up: past the slot's top the round would leave
		// the measured band, which is the signature this avoids.
		target = randInt((row.tls[0]+127)/128, row.tls[1]/128) * 128
	}

	filler := randLetters(randInt(16, 48))
	body := join(
		lit([]byte{0x03, 0x03}),
		randRaw(32),
		filler,
		randRaw(max(0, target-9-2-32-filler.wire())),
	)
	hs := join(u8(0x01), u24(body.wire()), body)
	return join(lit([]byte{0x16, 0x03, 0x01}), u16(hs.wire()), hs)
}

// dtlsSeq is the 48-bit record sequence number, drawn with the low byte
// where the first few records of a session have it.
func dtlsSeq() packet {
	return join(lit(randBytes(5)), u8(randInt(0, 4)))
}

// dtls12ClientHello builds a DTLS 1.2 record (RFC 6347 §4.1, §4.2.2):
// legacy record framing with epoch and sequence number, one unfragmented
// handshake message, and trailing padding inside the record length.
func dtls12ClientHello(row browserRow) packet {
	target := randInt(row.dtls[0], row.dtls[1])

	body := join(lit([]byte{0xfe, 0xfd}), randRaw(32))
	hs := join(u8(0x01), u24(body.wire()), lit([]byte{0x00, 0x00}), u24(0), u24(body.wire()), body)
	tail := randRaw(max(0, target-13-hs.wire()))

	return join(
		lit([]byte{0x16, 0xfe, 0xfd}), lit([]byte{0x00, 0x00}), dtlsSeq(),
		u16(hs.wire()+tail.wire()),
		hs, tail,
	)
}

// dtls13ClientHello builds a DTLS 1.3 ClientHello in the legacy framing and
// body shape (RFC 9147 §4, §5.3), ending in supported_versions (DTLS 1.3)
// and one GREASE extension (RFC 8701) whose declared length swallows the
// trailing padding, so the ClientHello parses out to its last byte.
func dtls13ClientHello(row browserRow) packet {
	target := randInt(row.dtls[0], row.dtls[1])
	// Everything outside the tail: record framing (13), handshake header
	// (12), legacy version and random (34), empty session and cookie (2),
	// the suite list (8), the compression list (2), the extensions length
	// (2), supported_versions (7) and the GREASE type and length (4).
	const fixed = 13 + 12 + 2 + 32 + 2 + 8 + 2 + 2 + 7 + 4
	tail := randRaw(max(0, target-fixed))

	// RFC 8701 GREASE extension types are 0xNANA: the byte 0xNA repeated.
	greaseByte := byte(randInt(0, 15))<<4 | 0x0a
	greaseType := int(greaseByte)<<8 | int(greaseByte)
	body := join(
		lit([]byte{0xfe, 0xfd}),
		randRaw(32),
		lit([]byte{0x00, 0x00}),
		lit([]byte{0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03}),
		lit([]byte{0x01, 0x00}),
		u16(7+4+tail.wire()),
		lit([]byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc}),
		u16(greaseType), u16(tail.wire()),
		tail,
	)
	hs := join(u8(0x01), u24(body.wire()), lit([]byte{0x00, 0x00}), u24(0), u24(body.wire()), body)
	return join(
		lit([]byte{0x16, 0xfe, 0xfd}), lit([]byte{0x00, 0x00}), dtlsSeq(),
		u16(hs.wire()),
		hs,
	)
}

// dnsNames are lookups a device makes on its own all day - resolvers,
// connectivity checks, update services. Drawn rather than generated:
// generated names are a signature of their own.
var dnsNames = []string{
	"dns.google", "cloudflare-dns.com", "one.one.one.one", "www.google.com",
	"play.googleapis.com", "detectportal.firefox.com", "captive.apple.com",
	"connectivitycheck.gstatic.com", "www.msftconnecttest.com", "time.cloudflare.com",
}

// dnsQuery builds a DNS query (RFC 1035 §4.1) with EDNS padding (RFC 6891):
// when the drawn size - U[64, min(512, MTU-20)], i.e. U[64, 512] over the
// legal MTUs - leaves room, the whole tail is the OPT padding option's data,
// so the query parses out to its last byte.
func dnsQuery() packet {
	target := randInt(64, 512)

	var qname packet
	for _, label := range strings.Split(dnsNames[randInt(0, len(dnsNames)-1)], ".") {
		qname = join(qname, u8(len(label)), litText(label))
	}
	qname = join(qname, u8(0)) // the root label that terminates every QNAME
	qtype := []byte{0x00, 0x01}
	if randInt(0, 1) == 1 {
		qtype = []byte{0x00, 0x1c}
	}
	question := join(qname, lit(qtype), lit([]byte{0x00, 0x01}))

	head := join(randRaw(2), lit([]byte{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}))

	// header, question and the OPT record's fixed 15 bytes have to fit;
	// past that the whole tail is the padding option's data.
	tail := randRaw(target - 12 - question.wire() - 15)
	if tail.wire() < 1 {
		return join(head, lit([]byte{0x00, 0x00}), question)
	}
	opt := join(
		lit([]byte{0x00}), u16(0x0029), u16(1232), u32(0),
		u16(4+tail.wire()),
		u16(0x000c), u16(tail.wire()),
		tail,
	)
	return join(head, lit([]byte{0x00, 0x01}), question, opt)
}

// noiseIKHandshake builds a WireGuard MessageInitiation - the Noise_IK
// handshake packet: type and reserved bytes, sender index, ephemeral key,
// encrypted static and timestamp, MAC1, and padding out to the row's nx size,
// so the packet is never the fixed 148 bytes every such packet has. The nx
// band is the fingerprint table's own (Any Tech ARCHITECT,
// src/shared/fingerprints.ts - 1200-1250 on every row); the small pad that
// table's pad-envelope rule also allows (U[10,40]-times-iv, capped 200) is
// its no-fingerprint fallback, which the profile-less slots already use.
func noiseIKHandshake(row browserRow) packet {
	target := min(randInt(row.nx[0], row.nx[1]), maxPacketBytes)
	return join(
		lit([]byte{0x01, 0x00, 0x00, 0x00}),
		randRaw(4),
		randRaw(32),
		randRaw(48),
		randRaw(28),
		randRaw(32),
		randRaw(max(target-148, 0)),
	)
}

// The STUN attribute type codes the profiles emit, pinned against the RFCs
// they come from: RFC 8489 §5/§14 for the STUN attributes, RFC 8445 §5.1.2.1
// for the ones an ICE connectivity check carries, and RFC 8656 §18.8 for
// REQUESTED-TRANSPORT. A code off the registers lands in the
// comprehension-required range as an unknown attribute and a strict parser
// rejects the message outright - the imitation falls apart at the first
// check. FINGERPRINT is pinned with the rest although stunHeader never emits
// it (see the note there). chains_test.go pins these to the RFC values.
const (
	stunUsername           = 0x0006 // USERNAME
	stunMessageIntegrity   = 0x0008 // MESSAGE-INTEGRITY, 20-byte HMAC-SHA1 value
	stunRealm              = 0x0014 // REALM
	stunNonce              = 0x0015 // NONCE
	stunRequestedTransport = 0x0019 // REQUESTED-TRANSPORT
	stunPriority           = 0x0024 // PRIORITY, 4-byte value
	stunUseCandidate       = 0x0025 // USE-CANDIDATE, no value
	stunFingerprint        = 0x8028 // FINGERPRINT, never emitted (see stunHeader)
	stunICEControlled      = 0x8029 // ICE-CONTROLLED, 8-byte tie-breaker value
	stunICEControlling     = 0x802A // ICE-CONTROLLING, 8-byte tie-breaker value
)

// stunAttr is one STUN attribute (RFC 8489 §5): the type, the length of the
// value alone, the value, and zero padding to a 4-byte boundary.
func stunAttr(kind int, value packet) packet {
	return join(u16(kind), u16(value.wire()), value, lit(make([]byte, (4-value.wire()%4)%4)))
}

// stunHeader is a STUN message header (RFC 8489 §5): the length counts the
// attributes after the magic cookie and transaction id. FINGERPRINT (§5.4)
// is never emitted - it is a CRC of the whole message, every variant here
// carries runtime-random fields, and a wrong fingerprint is worse than none.
func stunHeader(kind int, attrs packet) packet {
	return join(u16(kind), u16(attrs.wire()), lit([]byte{0x21, 0x12, 0xa4, 0x42}), randRaw(12), attrs)
}

// stunChain is the pre-handshake traffic of a WebRTC session (RFC 8489 §5
// for the shapes, §14 for TURN credentials): binding, allocate, a retry with
// credentials and an ICE check fill I1-I4, so a chain reads like a session
// rather than one repeated packet.
func stunChain() []packet {
	// REQUESTED-TRANSPORT's value is the transport protocol (17 = UDP) in its
	// first byte with RFFU zero (RFC 8656 §18.8).
	allocate := stunHeader(0x0003, stunAttr(stunRequestedTransport, lit([]byte{0x11, 0x00, 0x00, 0x00})))
	allocateAuth := stunHeader(0x0003, join(
		// long-term credentials: "<timestamp>:<user>"
		stunAttr(stunUsername, join(randDigits(randInt(9, 10)), litText(":"), randLetters(8))),
		stunAttr(stunRealm, join(randLetters(8), litText("."), randLetters(3))),
		stunAttr(stunNonce, randLetters(16)),
		stunAttr(stunMessageIntegrity, randRaw(20)),
	))

	iceCheck := []packet{
		stunAttr(stunUsername, join(randLetters(randInt(4, 8)), litText(":"), randLetters(randInt(4, 8)))),
	}
	// A check carries exactly one of ICE-CONTROLLING and ICE-CONTROLLED, with
	// the agent's 8-byte tie-breaker as the value (RFC 8445 §5.1.2.1).
	if randInt(0, 1) == 1 {
		iceCheck = append(iceCheck, stunAttr(stunICEControlling, randRaw(8)))
	} else {
		iceCheck = append(iceCheck, stunAttr(stunICEControlled, randRaw(8)))
	}
	if randInt(0, 1) == 1 {
		iceCheck = append(iceCheck, stunAttr(stunUseCandidate, nil))
	}
	priority := 110<<24 + randInt(0x1e00, 0xffff)<<8 + 255
	iceCheck = append(iceCheck, stunAttr(stunPriority, u32(priority)), stunAttr(stunMessageIntegrity, randRaw(20)))

	return []packet{
		stunHeader(0x0001, nil),
		allocate,
		allocateAuth,
		stunHeader(0x0001, join(iceCheck...)),
	}
}

// sipRegister builds the text of a SIP REGISTER (RFC 3261 §7.1, §10.2).
// Host and user repeat across the headers exactly as drawn - the run tags
// redraw at every send - while the branch, tag and Call-ID are drawn hex,
// the character set those fields have. Content-Length covers the body.
func sipRegister() packet {
	host := string(randText("abcdefghijklmnopqrstuvwxyz", randInt(6, 10))) +
		"." + [...]string{"com", "net", "org", "io"}[randInt(0, 3)]
	user := "user" + string(randText("0123456789", 4))
	branch := drawnText(hexDigits, 16)
	tag := drawnText(hexDigits, 5)
	callID := drawnText(hexDigits, 10)

	extra := min(randInt(5, 30)*randInt(1, 3), 120)
	raw := randInt(1, extra-1)
	body := join(randRaw(raw), randLetters(extra-raw))

	head := join(
		litText("REGISTER sip:"+host+" SIP/2.0\r\n"),
		litText("Via: SIP/2.0/UDP "+host+":5060;branch=z9hG4bK"), branch, litText(";rport\r\n"),
		litText("Max-Forwards: 70\r\n"),
		litText("From: <sip:"+user+"@"+host+">;tag="), tag, litText("\r\n"),
		litText("To: <sip:"+user+"@"+host+">\r\n"),
		litText("Call-ID: "), callID, litText("@"+host+"\r\n"),
		litText("CSeq: "+strconv.Itoa(randInt(1, 9999))+" REGISTER\r\n"),
		litText("Contact: <sip:"+user+"@"+host+">;expires=3600\r\n"),
		litText("User-Agent: Linphone/5.2.5\r\n"),
		litText("Content-Length: "+strconv.Itoa(body.wire())+"\r\n\r\n"),
	)
	return join(head, body)
}
