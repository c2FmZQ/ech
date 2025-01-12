package ech

import (
	"net"
	"strings"
	"unsafe"

	"golang.org/x/crypto/cryptobyte"
)

// https://datatracker.ietf.org/doc/html/rfc1035
type dnsMessage struct {
	id     uint16
	qr     uint8
	opCode uint8
	aa     uint8
	tc     uint8
	rd     uint8
	ra     uint8
	z      uint8
	rCode  uint8

	question   []dnsQuestion
	answer     []dnsRR
	authority  []dnsRR
	additional []dnsRR
}

type dnsQuestion struct {
	name  string
	typ   uint16
	class uint16
}

type dnsRR struct {
	name  string
	typ   uint16
	class uint16
	ttl   uint32
	data  any
}

func (m dnsMessage) bytes() []byte {
	s := cryptobyte.NewBuilder(nil)
	s.AddUint16(m.id)
	s.AddUint16(uint16(m.qr&1)<<15 | uint16(m.opCode&0xf)<<11 | uint16(m.aa&1)<<10 | uint16(m.tc&1)<<9 | uint16(m.rd&1)<<8 | uint16(m.ra&1)<<7 | uint16(m.rCode&0xf))
	s.AddUint16(uint16(len(m.question)))
	s.AddUint16(0)
	s.AddUint16(0)
	s.AddUint16(0)
	for _, v := range m.question {
		parts := strings.Split(strings.TrimSuffix(v.name, "."), ".")
		for _, p := range parts {
			s.AddUint8LengthPrefixed(func(s *cryptobyte.Builder) {
				s.AddBytes([]byte(p))
			})
		}
		s.AddUint8(0)
		s.AddUint16(v.typ)
		s.AddUint16(v.class)
	}
	return s.BytesOrPanic()
}

func decodeDNSMessage(m []byte) (dnsMessage, error) {
	return dnsDecoder{m}.decode()
}

type dnsDecoder struct {
	raw []byte
}

func (d dnsDecoder) decode() (dnsMessage, error) {
	var msg dnsMessage
	s := cryptobyte.String(d.raw)
	if !s.ReadUint16(&msg.id) {
		return msg, ErrDecodeError
	}
	var v uint16
	if !s.ReadUint16(&v) {
		return msg, ErrDecodeError
	}
	msg.qr = uint8((v & 0x8000) >> 15)
	msg.opCode = uint8((v & 0x7800) >> 11)
	msg.aa = uint8((v & 0x0400) >> 10)
	msg.tc = uint8((v & 0x0200) >> 9)
	msg.rd = uint8((v & 0x0100) >> 8)
	msg.ra = uint8((v & 0x0080) >> 7)
	msg.z = uint8((v & 0x0070) >> 4)
	msg.rCode = uint8(v & 0x000f)

	var qdCount uint16
	if !s.ReadUint16(&qdCount) {
		return msg, ErrDecodeError
	}
	var anCount uint16
	if !s.ReadUint16(&anCount) {
		return msg, ErrDecodeError
	}
	var nsCount uint16
	if !s.ReadUint16(&nsCount) {
		return msg, ErrDecodeError
	}
	var arCount uint16
	if !s.ReadUint16(&arCount) {
		return msg, ErrDecodeError
	}
	for n := 0; n < int(qdCount); n++ {
		var question dnsQuestion
		name, err := d.name(&s)
		if err != nil {
			return msg, err
		}
		question.name = name
		if !s.ReadUint16(&question.typ) {
			return msg, ErrDecodeError
		}
		if !s.ReadUint16(&question.class) {
			return msg, ErrDecodeError
		}
		msg.question = append(msg.question, question)
	}
	for n := 0; n < int(anCount); n++ {
		rr, err := d.rr(&s)
		if err != nil {
			return msg, err
		}
		msg.answer = append(msg.answer, rr)
	}
	for n := 0; n < int(nsCount); n++ {
		rr, err := d.rr(&s)
		if err != nil {
			return msg, err
		}
		msg.authority = append(msg.authority, rr)
	}
	for n := 0; n < int(arCount); n++ {
		rr, err := d.rr(&s)
		if err != nil {
			return msg, err
		}
		msg.additional = append(msg.additional, rr)
	}

	return msg, nil
}

func (d dnsDecoder) name(s *cryptobyte.String) (string, error) {
	labels, err := d.nameLabels(s)
	if err != nil {
		return "", err
	}
	return strings.Join(labels, "."), nil
}

func (d dnsDecoder) nameLabels(s *cryptobyte.String) ([]string, error) {
	var labels []string
	for {
		for !s.Empty() && (*s)[0]&0xc0 == 0xc0 { // pointer
			var offset uint16
			if !s.ReadUint16(&offset) {
				return nil, ErrDecodeError
			}
			offset &= 0x3fff
			if int(offset) > len(d.raw) || uintptr(unsafe.Pointer(&d.raw[offset])) >= uintptr(unsafe.Pointer(&(*s)[0])) {
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

func (d dnsDecoder) rr(s *cryptobyte.String) (dnsRR, error) {
	var rr dnsRR
	n, err := d.name(s)
	if err != nil {
		return rr, err
	}
	rr.name = n
	if !s.ReadUint16(&rr.typ) {
		return rr, ErrDecodeError
	}
	if !s.ReadUint16(&rr.class) {
		return rr, ErrDecodeError
	}
	if !s.ReadUint32(&rr.ttl) {
		return rr, ErrDecodeError
	}
	var data cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&data) {
		return rr, ErrDecodeError
	}
	switch rr.typ {
	case 1: // A
		v := net.IP(data)
		if v == nil {
			return rr, ErrDecodeError
		}
		rr.data = v.String()
	case 5: // CNAME
		n, err := d.name(&data)
		if err != nil {
			return rr, err
		}
		rr.data = n
	case 28: // AAAA
		v := net.IP(data)
		if v == nil {
			return rr, ErrDecodeError
		}
		rr.data = v.String()
	case 65: // HTTPS
		v, err := d.https(data)
		if err != nil {
			return rr, err
		}
		rr.data = v
	default:
		rr.data = []byte(data)
	}
	return rr, nil
}

func (d dnsDecoder) https(b []byte) (HTTPS, error) {
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
