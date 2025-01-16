package dns

import (
	"net"
	"reflect"
	"testing"
)

func TestMessageA(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x28, 0x00, 0x04, 0x8e, 0xfa, 0xb0, 0x04,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x0,
		Question: []Question{{
			Name:  "www.google.com",
			Type:  0x1,
			Class: 0x1,
		}},
		Answer: []RR{{
			Name:  "www.google.com",
			Type:  0x1,
			Class: 0x1,
			TTL:   0x128,
			Data:  net.IP{0x8e, 0xfa, 0xb0, 0x4},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}

func TestMessageAAAA(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x55, 0x00, 0x10, 0x26, 0x07, 0xf8, 0xb0,
		0x40, 0x07, 0x08, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x04,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x0,
		Question: []Question{{
			Name:  "www.google.com",
			Type:  0x1c,
			Class: 0x1,
		}},
		Answer: []RR{{
			Name:  "www.google.com",
			Type:  0x1c,
			Class: 0x1,
			TTL:   0x55,
			Data:  net.IP{0x26, 0x7, 0xf8, 0xb0, 0x40, 0x7, 0x8, 0x18, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x4},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}

func TestMessageMX(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
		0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x0f, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x0f,
		0x00, 0x01, 0x00, 0x00, 0x00, 0xe9, 0x00, 0x09, 0x00, 0x0a, 0x04, 0x73, 0x6d, 0x74, 0x70, 0xc0,
		0x0c,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x0,
		Question: []Question{{
			Name:  "google.com",
			Type:  0xf,
			Class: 0x1,
		}},
		Answer: []RR{{
			Name:  "google.com",
			Type:  0xf,
			Class: 0x1,
			TTL:   0xe9,
			Data: MX{
				Preference: 0xa,
				Exchange:   "smtp.google.com",
			},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}

func TestMessageNS(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
		0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x02, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x02,
		0x00, 0x01, 0x00, 0x05, 0x33, 0xd5, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x0c, 0xc0, 0x0c,
		0x00, 0x02, 0x00, 0x01, 0x00, 0x05, 0x33, 0xd5, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x33, 0xc0, 0x0c,
		0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, 0x33, 0xd5, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x31,
		0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, 0x33, 0xd5, 0x00, 0x06, 0x03, 0x6e,
		0x73, 0x32, 0xc0, 0x0c,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x0,
		Question: []Question{{
			Name:  "google.com",
			Type:  0x2,
			Class: 0x1,
		}},
		Answer: []RR{
			{
				Name:  "google.com",
				Type:  0x2,
				Class: 0x1,
				TTL:   0x533d5,
				Data:  "ns4.google.com",
			}, {
				Name:  "google.com",
				Type:  0x2,
				Class: 0x1,
				TTL:   0x533d5,
				Data:  "ns3.google.com",
			}, {
				Name:  "google.com",
				Type:  0x2,
				Class: 0x1,
				TTL:   0x533d5,
				Data:  "ns1.google.com",
			}, {Name: "google.com",
				Type:  0x2,
				Class: 0x1,
				TTL:   0x533d5,
				Data:  "ns2.google.com",
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}

func TestMessagePTR(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x34, 0x36, 0x02,
		0x33, 0x32, 0x03, 0x32, 0x35, 0x31, 0x03, 0x31, 0x34, 0x32, 0x07, 0x69, 0x6e, 0x2d, 0x61, 0x64,
		0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x0c,
		0x00, 0x01, 0x00, 0x01, 0x51, 0x7c, 0x00, 0x1b, 0x0f, 0x73, 0x66, 0x6f, 0x30, 0x33, 0x73, 0x32,
		0x36, 0x2d, 0x69, 0x6e, 0x2d, 0x66, 0x31, 0x34, 0x05, 0x31, 0x65, 0x31, 0x30, 0x30, 0x03, 0x6e,
		0x65, 0x74, 0x00,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x0,
		Question: []Question{{
			Name:  "46.32.251.142.in-addr.arpa",
			Type:  0xc,
			Class: 0x1,
		}},
		Answer: []RR{{
			Name:  "46.32.251.142.in-addr.arpa",
			Type:  0xc,
			Class: 0x1,
			TTL:   0x1517c,
			Data:  "sfo03s26-in-f14.1e100.net",
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}

func TestMessageSRV(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x5f, 0x69, 0x6d,
		0x61, 0x70, 0x73, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x03, 0x63,
		0x6f, 0x6d, 0x00, 0x00, 0x21, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x21, 0x00, 0x01, 0x00, 0x01, 0x51,
		0x80, 0x00, 0x16, 0x00, 0x05, 0x00, 0x00, 0x03, 0xe1, 0x04, 0x69, 0x6d, 0x61, 0x70, 0x05, 0x67,
		0x6d, 0x61, 0x69, 0x6c, 0x03, 0x63, 0x6f, 0x6d, 0x00,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x0,
		Question: []Question{{
			Name:  "_imaps._tcp.gmail.com",
			Type:  0x21,
			Class: 0x1,
		}},
		Answer: []RR{{
			Name:  "_imaps._tcp.gmail.com",
			Type:  0x21,
			Class: 0x1,
			TTL:   0x15180,
			Data: SRV{
				Priority: 0x5,
				Weight:   0x0,
				Port:     0x3e1,
				Target:   "imap.gmail.com",
			}},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}

func TestMessageCAA(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f,
		0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x01, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x01, 0x01,
		0x00, 0x01, 0x00, 0x01, 0x51, 0x80, 0x00, 0x0f, 0x00, 0x05, 0x69, 0x73, 0x73, 0x75, 0x65, 0x70,
		0x6b, 0x69, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x0,
		Question: []Question{{
			Name:  "google.com",
			Type:  0x101,
			Class: 0x1,
		}},
		Answer: []RR{{
			Name:  "google.com",
			Type:  0x101,
			Class: 0x1,
			TTL:   0x15180,
			Data: CAA{
				Flags: 0x0,
				Tag:   "issue",
				Value: "pki.goog",
			}},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}

func TestMessageHTTPS(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x0f, 0x74, 0x74, 0x62, 0x74, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x70, 0x72, 0x69, 0x73, 0x65,
		0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x41, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2c, 0x00, 0x8a, 0x00, 0x0c, 0x03, 0x66, 0x6f, 0x6f, 0x00, 0x00, 0x01, 0x00,
		0x06, 0x02, 0x68, 0x33, 0x02, 0x68, 0x32, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x04,
		0xd2, 0x00, 0x04, 0x00, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00, 0x4f, 0x00, 0x4d, 0xfe,
		0x0d, 0x00, 0x49, 0x00, 0x00, 0x20, 0x00, 0x20, 0x2a, 0x2b, 0x6d, 0xd6, 0xd8, 0x7c, 0x63, 0xde,
		0x40, 0x88, 0x77, 0xd0, 0x21, 0xd6, 0xb1, 0x3b, 0x13, 0x20, 0x6c, 0x17, 0x25, 0x5a, 0x52, 0x5d,
		0x70, 0x4c, 0xbf, 0xdc, 0x11, 0x41, 0x44, 0x41, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01,
		0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x22, 0x12, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2e, 0x65,
		0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x06, 0x00, 0x10,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x0,
		Question: []Question{{
			Name:  "test.ttbtenterprises.com",
			Type:  0x41,
			Class: 0x1,
		}},
		Answer: []RR{{
			Name:  "test.ttbtenterprises.com",
			Type:  0x41,
			Class: 0x1,
			TTL:   0x12c,
			Data: HTTPS{
				Priority:      0xc,
				Target:        "foo",
				ALPN:          []string{"h3", "h2"},
				NoDefaultALPN: true,
				Port:          0x4d2,
				IPv4Hint:      []net.IP{{0x7f, 0x0, 0x0, 0x1}},
				IPv6Hint:      []net.IP{{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}},
				ECH: []uint8{
					0x00, 0x4d, 0xfe, 0x0d, 0x00, 0x49, 0x00, 0x00, 0x20, 0x00, 0x20, 0x2a, 0x2b, 0x6d, 0xd6, 0xd8,
					0x7c, 0x63, 0xde, 0x40, 0x88, 0x77, 0xd0, 0x21, 0xd6, 0xb1, 0x3b, 0x13, 0x20, 0x6c, 0x17, 0x25,
					0x5a, 0x52, 0x5d, 0x70, 0x4c, 0xbf, 0xdc, 0x11, 0x41, 0x44, 0x41, 0x00, 0x0c, 0x00, 0x01, 0x00,
					0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x22, 0x12, 0x70, 0x75, 0x62, 0x6c, 0x69,
					0x63, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
				},
			},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}

func TestMessageLOC(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x53, 0x57, 0x31,
		0x41, 0x32, 0x41, 0x41, 0x04, 0x66, 0x69, 0x6e, 0x64, 0x02, 0x6d, 0x65, 0x02, 0x75, 0x6b, 0x00,
		0x00, 0x1d, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1d, 0x00, 0x01, 0x00, 0x27, 0x8d, 0x00, 0x00, 0x10,
		0x00, 0x00, 0x00, 0x00, 0x8b, 0x0d, 0x2c, 0x8c, 0x7f, 0xf8, 0xfc, 0xa5, 0x00, 0x98, 0x96, 0x80,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x0,
		Question: []Question{{
			Name:  "SW1A2AA.find.me.uk",
			Type:  0x1d,
			Class: 0x1,
		}},
		Answer: []RR{{
			Name:  "SW1A2AA.find.me.uk",
			Type:  0x1d,
			Class: 0x1,
			TTL:   0x278d00,
			Data: LOC{
				Version:   0x0,
				Size:      0x0,
				HorizPre:  0x0,
				VertPre:   0x0,
				Latitude:  51.50354111111111,
				Longitude: -0.12766972222222223,
				Altitude:  0,
			}},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}

func TestMessageURI(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x74, 0x65, 0x73,
		0x74, 0x0f, 0x74, 0x74, 0x62, 0x74, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x70, 0x72, 0x69, 0x73, 0x65,
		0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x01, 0x00, 0x00, 0x01, 0xc0, 0x0c, 0x01, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x2c, 0x00, 0x23, 0x00, 0x01, 0x00, 0x01, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a,
		0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x74, 0x74, 0x62, 0x74, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x70,
		0x72, 0x69, 0x73, 0x65, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x0,
		Question: []Question{{
			Name:  "test.ttbtenterprises.com",
			Type:  0x100,
			Class: 0x1,
		}},
		Answer: []RR{{
			Name:  "test.ttbtenterprises.com",
			Type:  0x100,
			Class: 0x1,
			TTL:   0x12c,
			Data: URI{
				Priority: 0x1,
				Weight:   0x1,
				Target:   "https://www.ttbtenterprises.com",
			}},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}

func TestMessageNXDomain(t *testing.T) {
	m := []byte{
		0x00, 0x00, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x06, 0x78, 0x78, 0x78,
		0x78, 0x78, 0x78, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01, 0xc0, 0x13, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x2c,
		0x02, 0x6e, 0x73, 0x05, 0x69, 0x63, 0x61, 0x6e, 0x6e, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x03, 0x6e,
		0x6f, 0x63, 0x03, 0x64, 0x6e, 0x73, 0xc0, 0x33, 0x78, 0xb3, 0x38, 0x01, 0x00, 0x00, 0x1c, 0x20,
		0x00, 0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, 0x00, 0x00, 0x00, 0x0e, 0x10,
	}
	got, err := DecodeMessage(m)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	want := &Message{
		ID:     0x0,
		QR:     0x1,
		OpCode: 0x0,
		AA:     0x0,
		TC:     0x0,
		RD:     0x1,
		RA:     0x1,
		RCode:  0x3,
		Question: []Question{{
			Name:  "xxxxxx.example.com",
			Type:  0x1,
			Class: 0x1,
		}},
		Authority: []RR{{
			Name:  "example.com",
			Type:  0x6,
			Class: 0x1,
			TTL:   0xe10,
			Data: SOA{
				MName:   "ns.icann.org",
				RName:   "noc.dns.icann.org",
				Serial:  0x78b33801,
				Refresh: 0x1c20,
				Retry:   0xe10,
				Expire:  0x127500,
				Minimum: 0xe10,
			},
		}},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Got %#v, want %#v", got, want)
	}
}
