package dns

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/crypto/cryptobyte"
)

var (
	ErrDecodeError = errors.New("decode error")

	// A map of Resource Record types.
	// https://en.wikipedia.org/wiki/List_of_DNS_record_types
	rrTypes = map[string]uint16{
		"A":          1,     // RFC 1035
		"AAAA":       28,    // RFC 3596
		"AFSDB":      18,    // RFC 1183
		"APL":        42,    // RFC 3123
		"CAA":        257,   // RFC 6844
		"CDNSKEY":    60,    // RFC 7344
		"CDS":        59,    // RFC 7344
		"CERT":       37,    // RFC 4398
		"CNAME":      5,     // RFC 1035
		"CSYNC":      62,    // RFC 7477
		"DHCID":      49,    // RFC 4701
		"DLV":        32769, // RFC 4431
		"DNAME":      39,    // RFC 6672
		"DNSKEY":     48,    // RFC 4034
		"DS":         43,    // RFC 4034
		"EUI48":      108,   // RFC 7043
		"EUI64":      109,   // RFC 7043
		"HINFO":      13,    // RFC 8482
		"HIP":        55,    // RFC 8005
		"HTTPS":      65,    // RFC 9460
		"IPSECKEY":   45,    // RFC 4025
		"KEY":        25,    // RFC 2535 and RFC 2930
		"KX":         36,    // RFC 2230
		"LOC":        29,    // RFC 1876
		"MX":         15,    // RFC 1035 and RFC 7505
		"NAPTR":      35,    // RFC 3403
		"NS":         2,     // RFC 1035
		"NSEC":       47,    // RFC 4034
		"NSEC3":      50,    // RFC 5155
		"NSEC3PARAM": 51,    // RFC 5155
		"OPENPGPKEY": 61,    // RFC 7929
		"PTR":        12,    // RFC 1035
		"RP":         17,    // RFC 1183
		"RRSIG":      46,    // RFC 4034
		"SIG":        24,    // RFC 2535
		"SMIMEA":     53,    // RFC 8162
		"SOA":        6,     // RFC 1035 and RFC 2308
		"SRV":        33,    // RFC 2782
		"SSHFP":      44,    // RFC 4255
		"SVCB":       64,    // RFC 9460
		"TA":         32768, //
		"TKEY":       249,   // RFC 2930
		"TLSA":       52,    // RFC 6698
		"TSIG":       250,   // RFC 2845
		"TXT":        16,    // RFC 1035
		"URI":        256,   // RFC 7553
		"ZONEMD":     63,    // RFC 8976
	}
)

// RRType returns the RR type id for a type name.
func RRType(t string) uint16 {
	return rrTypes[strings.ToUpper(t)]
}

// Message is a RFC 1035 DNS Message.
type Message struct {
	// Header
	ID     uint16 `json:"id,omitempty"`
	QR     uint8  `json:"qr"`
	OpCode uint8  `json:"opcode,omitempty"`
	AA     uint8  `json:"aa,omitempty"`
	TC     uint8  `json:"tc,omitempty"`
	RD     uint8  `json:"rd,omitempty"`
	RA     uint8  `json:"ra,omitempty"`
	RCode  uint8  `json:"rcode"`

	// Question section
	Question []Question `json:"question,omitempty"`
	// Answer section
	Answer []RR `json:"answer,omitempty"`
	// Authority section
	Authority []RR `json:"authority,omitempty"`
	// Additional information section
	Additional []RR `json:"additional,omitempty"`
}

// A question for a name server.
type Question struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
}

// A Resource Record.
type RR struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  any    `json:"data"`
}

// MX represents a MX Resource Record.
type MX struct {
	Preference uint16 `json:"preference"`
	Exchange   string `json:"exchange"`
}

// TXT represents a TXT Resource Record.
type TXT []string

// SOA represents a SOA Resource Record.
type SOA struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// CAA represents a CAA Resource Record.
type CAA struct {
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// CERT represents a CERT Resource Record.
type CERT struct {
	Type        uint16 `json:"type"`
	KeyTag      uint16 `json:"keytag"`
	Algorithm   uint8  `json:"algorithm"`
	Certificate []byte `json:"certificate"`
}

// DNSKEY represents a DNSKEY Resource Record.
type DNSKEY struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey []byte `json:"publickey"`
}

// DS represents a DS Resource Record.
type DS struct {
	KeyTag     uint16 `json:"keytag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digesttype"`
	Digest     []byte `json:"digest"`
}

// RRSIG represents a RRSIG Resource Record.
type RRSIG struct {
	TypeCovered         uint16 `json:"typecovered"`
	Algorithm           uint8  `json:"algorithm"`
	Labels              uint8  `json:"labels"`
	OriginalTTL         uint32 `json:"originalttl"`
	SignatureExpiration uint32 `json:"signatureexpiration"`
	SignatureInception  uint32 `json:"signatureinception"`
	KeyTag              uint16 `json:"keytag"`
	SignerName          string `json:"signername"`
	Signature           []byte `json:"signature"`
}

// NSEC represents a NSEC Resource Record.
type NSEC struct {
	NextDomainName string `json:"nextdomainname"`
	TypeBitMaps    []byte `json:"typebitmaps"`
}

// LOC represents a LOC Resource Record. RFC 1876
type LOC struct {
	Version   uint8   `json:"version"`
	Size      float64 `json:"size"`      // meters
	HorizPre  float64 `json:"horizpre"`  // meters
	VertPre   float64 `json:"vertpre"`   // meters
	Latitude  float64 `json:"latitude"`  // degrees
	Longitude float64 `json:"longitude"` // degrees
	Altitude  float64 `json:"altitude"`  // meters above reference altitude
}

// SRV represents a SRV Resource Record.
type SRV struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

// SVCB represents a SVCB Resource Record. RFC 9460
type SVCB struct {
	Priority uint16      `json:"priority"`
	Target   string      `json:"target"`
	Params   []SVCBParam `json:"params"`
}

type SVCBParam struct {
	Key   uint16 `json:"key"`
	Value []byte `json:"value,omitempty"`
}

// HTTPS represents a HTTPS Resource Record. RFC 9460
type HTTPS struct {
	Priority      uint16   `json:"priority"`
	Target        string   `json:"target,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	NoDefaultALPN bool     `json:"no-default-alpn,omitempty"`
	Port          uint16   `json:"port,omitempty"`
	IPv4Hint      net.IP   `json:"ipv4hint,omitempty"`
	IPv6Hint      net.IP   `json:"ipv6hint,omitempty"`
	ECH           []byte   `json:"ech,omitempty"`
}

// URI represents a URI Resource Record. RFC 7553
type URI struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Target   string `json:"target"`
}

// Bytes returns the serialized message. It includes only the header and the
// question section.
func (m Message) Bytes() []byte {
	s := cryptobyte.NewBuilder(nil)
	s.AddUint16(m.ID)
	s.AddUint16(uint16(m.QR&1)<<15 | uint16(m.OpCode&0xf)<<11 | uint16(m.AA&1)<<10 | uint16(m.TC&1)<<9 | uint16(m.RD&1)<<8 | uint16(m.RA&1)<<7 | uint16(m.RCode&0xf))
	s.AddUint16(uint16(len(m.Question)))
	s.AddUint16(0)
	s.AddUint16(0)
	s.AddUint16(0)
	for _, v := range m.Question {
		parts := strings.Split(strings.TrimSuffix(v.Name, "."), ".")
		for _, p := range parts {
			s.AddUint8LengthPrefixed(func(s *cryptobyte.Builder) {
				s.AddBytes([]byte(p))
			})
		}
		s.AddUint8(0)
		s.AddUint16(v.Type)
		s.AddUint16(v.Class)
	}
	return s.BytesOrPanic()
}

// DecodeMessage decodes a DNS message.
func DecodeMessage(m []byte) (*Message, error) {
	return decoder{m}.decode()
}

type decoder struct {
	raw []byte
}

func (d decoder) decode() (*Message, error) {
	var msg Message
	s := cryptobyte.String(d.raw)
	if !s.ReadUint16(&msg.ID) {
		return nil, ErrDecodeError
	}
	var v uint16
	if !s.ReadUint16(&v) {
		return nil, ErrDecodeError
	}
	msg.QR = uint8((v & 0x8000) >> 15)
	msg.OpCode = uint8((v & 0x7800) >> 11)
	msg.AA = uint8((v & 0x0400) >> 10)
	msg.TC = uint8((v & 0x0200) >> 9)
	msg.RD = uint8((v & 0x0100) >> 8)
	msg.RA = uint8((v & 0x0080) >> 7)
	msg.RCode = uint8(v & 0x000f)

	var qdCount uint16
	if !s.ReadUint16(&qdCount) {
		return nil, ErrDecodeError
	}
	var anCount uint16
	if !s.ReadUint16(&anCount) {
		return nil, ErrDecodeError
	}
	var nsCount uint16
	if !s.ReadUint16(&nsCount) {
		return nil, ErrDecodeError
	}
	var arCount uint16
	if !s.ReadUint16(&arCount) {
		return nil, ErrDecodeError
	}
	for n := 0; n < int(qdCount); n++ {
		var question Question
		name, err := d.name(&s)
		if err != nil {
			return nil, err
		}
		question.Name = name
		if !s.ReadUint16(&question.Type) {
			return nil, ErrDecodeError
		}
		if !s.ReadUint16(&question.Class) {
			return nil, ErrDecodeError
		}
		msg.Question = append(msg.Question, question)
	}
	for n := 0; n < int(anCount); n++ {
		rr, err := d.rr(&s)
		if err != nil {
			return nil, err
		}
		msg.Answer = append(msg.Answer, rr)
	}
	for n := 0; n < int(nsCount); n++ {
		rr, err := d.rr(&s)
		if err != nil {
			return nil, err
		}
		msg.Authority = append(msg.Authority, rr)
	}
	for n := 0; n < int(arCount); n++ {
		rr, err := d.rr(&s)
		if err != nil {
			return nil, err
		}
		msg.Additional = append(msg.Additional, rr)
	}

	return &msg, nil
}

func (d decoder) name(s *cryptobyte.String) (string, error) {
	labels, err := d.nameLabels(s)
	if err != nil {
		return "", err
	}
	return strings.Join(labels, "."), nil
}

func (d decoder) nameLabels(s *cryptobyte.String) ([]string, error) {
	var labels []string
	for {
		for !s.Empty() && (*s)[0]&0xc0 == 0xc0 { // pointer
			current := uintptr(unsafe.Pointer(&(*s)[0]))
			var offset uint16
			if !s.ReadUint16(&offset) {
				return nil, ErrDecodeError
			}
			offset &= 0x3fff
			if int(offset) >= len(d.raw) || uintptr(unsafe.Pointer(&d.raw[offset])) >= current {
				return nil, ErrDecodeError
			}
			ss := cryptobyte.String(d.raw[offset:])
			s = &ss
		}
		var name cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&name) {
			return nil, ErrDecodeError
		}
		if len(name) == 0 {
			break
		}
		labels = append(labels, string(name))
	}
	return labels, nil
}

func (d decoder) rr(s *cryptobyte.String) (RR, error) {
	var rr RR
	n, err := d.name(s)
	if err != nil {
		return rr, err
	}
	rr.Name = n
	if !s.ReadUint16(&rr.Type) {
		return rr, ErrDecodeError
	}
	if !s.ReadUint16(&rr.Class) {
		return rr, ErrDecodeError
	}
	if !s.ReadUint32(&rr.TTL) {
		return rr, ErrDecodeError
	}
	var data cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&data) {
		return rr, ErrDecodeError
	}
	switch rr.Type {
	case 1: // A
		v := net.IP(data)
		if v == nil || len(v) != 4 {
			return rr, ErrDecodeError
		}
		rr.Data = v
	case 2, 5, 12: // NS, CNAME, PTR
		n, err := d.name(&data)
		if err != nil {
			return rr, err
		}
		rr.Data = n
	case 6: // SOA
		v, err := d.soa(&data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 15: // MX
		v, err := d.mx(&data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 16: // TXT
		var result []string
		for !data.Empty() {
			var v cryptobyte.String
			if !data.ReadUint8LengthPrefixed(&v) {
				return rr, ErrDecodeError
			}
			result = append(result, string(v))
		}
		rr.Data = TXT(result)
	case 28: // AAAA
		v := net.IP(data)
		if v == nil || len(v) != 16 {
			return rr, ErrDecodeError
		}
		rr.Data = v
	case 29: // LOC
		v, err := d.loc(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 33: // SRV
		v, err := d.srv(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 37: // CERT
		v, err := d.cert(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 43: // DS
		v, err := d.ds(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 46: // RRSIG
		v, err := d.rrsig(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 47: // NSEC
		v, err := d.nsec(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 48: // DNSKEY
		v, err := d.dnskey(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 64: // SVCB
		v, err := d.svcb(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 65: // HTTPS
		v, err := d.https(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 256: // URI
		v, err := d.uri(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	case 257: // CAA
		v, err := d.caa(data)
		if err != nil {
			return rr, err
		}
		rr.Data = v
	default:
		rr.Data = []byte(data)
	}
	return rr, nil
}

func (d decoder) mx(s *cryptobyte.String) (MX, error) {
	var result MX
	if !s.ReadUint16(&result.Preference) {
		return result, ErrDecodeError
	}
	exchange, err := d.name(s)
	if err != nil {
		return result, err
	}
	result.Exchange = exchange
	return result, nil
}

func (d decoder) soa(s *cryptobyte.String) (SOA, error) {
	var result SOA
	mName, err := d.name(s)
	if err != nil {
		return result, err
	}
	result.MName = mName
	rName, err := d.name(s)
	if err != nil {
		return result, err
	}
	result.RName = rName
	if !s.ReadUint32(&result.Serial) {
		return result, ErrDecodeError
	}
	if !s.ReadUint32(&result.Refresh) {
		return result, ErrDecodeError
	}
	if !s.ReadUint32(&result.Retry) {
		return result, ErrDecodeError
	}
	if !s.ReadUint32(&result.Expire) {
		return result, ErrDecodeError
	}
	if !s.ReadUint32(&result.Minimum) {
		return result, ErrDecodeError
	}
	return result, nil
}

func (d decoder) loc(b []byte) (LOC, error) {
	var result LOC
	s := cryptobyte.String(b)
	if !s.ReadUint8(&result.Version) {
		return result, ErrDecodeError
	}
	var p uint8
	prec := func(v uint8) float64 {
		m := float64(v & 0xf0 >> 4)
		e := int(v & 0x0f)
		return m * math.Pow10(e) / 100
	}
	if !s.ReadUint8(&p) {
		return result, ErrDecodeError
	}
	result.Size = prec(p)
	if !s.ReadUint8(&p) {
		return result, ErrDecodeError
	}
	result.HorizPre = prec(p)
	if !s.ReadUint8(&p) {
		return result, ErrDecodeError
	}
	result.VertPre = prec(p)

	var v uint32
	if !s.ReadUint32(&v) {
		return result, ErrDecodeError
	}
	result.Latitude = float64(int64(v)-0x80000000) / 3600000
	if !s.ReadUint32(&v) {
		return result, ErrDecodeError
	}
	result.Longitude = float64(int64(v)-0x80000000) / 3600000
	if !s.ReadUint32(&v) {
		return result, ErrDecodeError
	}
	result.Altitude = float64(int64(v)-10000000) / 100
	return result, nil
}

func (d decoder) srv(b []byte) (SRV, error) {
	var result SRV
	s := cryptobyte.String(b)
	if !s.ReadUint16(&result.Priority) {
		return result, ErrDecodeError
	}
	if !s.ReadUint16(&result.Weight) {
		return result, ErrDecodeError
	}
	if !s.ReadUint16(&result.Port) {
		return result, ErrDecodeError
	}
	name, err := d.name(&s)
	if err != nil {
		return result, err
	}
	result.Target = name
	return result, nil
}

func (d decoder) svcb(b []byte) (SVCB, error) {
	var result SVCB
	s := cryptobyte.String(b)
	if !s.ReadUint16(&result.Priority) {
		return result, ErrDecodeError
	}
	name, err := d.name(&s)
	if err != nil {
		return result, err
	}
	result.Target = name
	for !s.Empty() {
		var key uint16
		if !s.ReadUint16(&key) {
			return result, ErrDecodeError
		}
		var value cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&value) {
			return result, ErrDecodeError
		}
		result.Params = append(result.Params, SVCBParam{Key: key, Value: value})
	}
	return result, nil
}

func (d decoder) https(b []byte) (HTTPS, error) {
	var result HTTPS
	s := cryptobyte.String(b)
	var svcPriority uint16
	if !s.ReadUint16(&svcPriority) {
		return result, ErrDecodeError
	}
	result.Priority = svcPriority
	name, err := d.name(&s)
	if err != nil {
		return result, err
	}
	result.Target = name
	for !s.Empty() {
		var key uint16
		if !s.ReadUint16(&key) {
			return result, ErrDecodeError
		}
		var value cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&value) {
			return result, ErrDecodeError
		}
		switch key {
		case 0: // mandatory keys
		case 1: // alpn
			for !value.Empty() {
				var proto cryptobyte.String
				if !value.ReadUint8LengthPrefixed(&proto) {
					return result, ErrDecodeError
				}
				result.ALPN = append(result.ALPN, string(proto))
			}
		case 2: // no-default-alpn
			result.NoDefaultALPN = true
		case 3: // port
			if !value.ReadUint16(&result.Port) {
				return result, ErrDecodeError
			}
		case 4: // ipv4hint
			result.IPv4Hint = net.IP(value)
		case 5: // ECH
			result.ECH = value
		case 6: // ipv6hint
			result.IPv6Hint = net.IP(value)
		}
	}
	return result, nil
}

func (h HTTPS) String() string {
	s := fmt.Sprintf("%d %s.", h.Priority, h.Target)
	if len(h.ALPN) > 0 {
		s += fmt.Sprintf(" alpn=%q", strings.Join(h.ALPN, ","))
	}
	if h.NoDefaultALPN {
		s += " no-default-alpn"
	}
	if h.Port > 0 {
		s += fmt.Sprintf(" port=%d", h.Port)
	}
	if len(h.IPv4Hint) > 0 {
		s += fmt.Sprintf(" ipv4hint=%s", h.IPv4Hint)
	}
	if len(h.IPv6Hint) > 0 {
		s += fmt.Sprintf(" ipv6hint=%s", h.IPv6Hint)
	}
	if len(h.ECH) > 0 {
		s += fmt.Sprintf(" ech=%q", base64.StdEncoding.EncodeToString(h.ECH))
	}
	return s
}

func (d decoder) cert(b []byte) (CERT, error) {
	var result CERT
	s := cryptobyte.String(b)
	if !s.ReadUint16(&result.Type) {
		return result, ErrDecodeError
	}
	if !s.ReadUint16(&result.KeyTag) {
		return result, ErrDecodeError
	}
	if !s.ReadUint8(&result.Algorithm) {
		return result, ErrDecodeError
	}
	result.Certificate = s
	return result, nil
}

func (d decoder) ds(b []byte) (DS, error) {
	var result DS
	s := cryptobyte.String(b)
	if !s.ReadUint16(&result.KeyTag) {
		return result, ErrDecodeError
	}
	if !s.ReadUint8(&result.Algorithm) {
		return result, ErrDecodeError
	}
	if !s.ReadUint8(&result.DigestType) {
		return result, ErrDecodeError
	}
	result.Digest = s
	return result, nil
}

func (d decoder) dnskey(b []byte) (DNSKEY, error) {
	var result DNSKEY
	s := cryptobyte.String(b)
	if !s.ReadUint16(&result.Flags) {
		return result, ErrDecodeError
	}
	if !s.ReadUint8(&result.Protocol) {
		return result, ErrDecodeError
	}
	if !s.ReadUint8(&result.Algorithm) {
		return result, ErrDecodeError
	}
	result.PublicKey = s
	return result, nil
}

func (d decoder) nsec(b []byte) (NSEC, error) {
	var result NSEC
	s := cryptobyte.String(b)
	name, err := d.name(&s)
	if err != nil {
		return result, err
	}
	result.NextDomainName = name
	result.TypeBitMaps = s
	return result, nil
}

func (d decoder) rrsig(b []byte) (RRSIG, error) {
	var result RRSIG
	s := cryptobyte.String(b)
	if !s.ReadUint16(&result.TypeCovered) {
		return result, ErrDecodeError
	}
	if !s.ReadUint8(&result.Algorithm) {
		return result, ErrDecodeError
	}
	if !s.ReadUint8(&result.Labels) {
		return result, ErrDecodeError
	}
	if !s.ReadUint32(&result.OriginalTTL) {
		return result, ErrDecodeError
	}
	if !s.ReadUint32(&result.SignatureExpiration) {
		return result, ErrDecodeError
	}
	if !s.ReadUint32(&result.SignatureInception) {
		return result, ErrDecodeError
	}
	if !s.ReadUint16(&result.KeyTag) {
		return result, ErrDecodeError
	}
	name, err := d.name(&s)
	if err != nil {
		return result, err
	}
	result.SignerName = name
	result.Signature = s
	return result, nil
}

func (d decoder) uri(b []byte) (URI, error) {
	var result URI
	s := cryptobyte.String(b)
	if !s.ReadUint16(&result.Priority) {
		return result, ErrDecodeError
	}
	if !s.ReadUint16(&result.Weight) {
		return result, ErrDecodeError
	}
	result.Target = string(s)
	return result, nil
}

func (d decoder) caa(b []byte) (CAA, error) {
	var result CAA
	s := cryptobyte.String(b)
	if !s.ReadUint8(&result.Flags) {
		return result, ErrDecodeError
	}
	var v cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&v) {
		return result, ErrDecodeError
	}
	result.Tag = string(v)
	result.Value = string(s)
	return result, nil
}
