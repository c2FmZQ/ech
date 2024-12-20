package ech

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	"github.com/c2FmZQ/ech/internal/hpke"
	"golang.org/x/crypto/cryptobyte"
)

func newCert(names ...string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ecdsa.GenerateKey: %w", err)
	}
	now := time.Now()
	templ := &x509.Certificate{
		Issuer:                pkix.Name{CommonName: names[0]},
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              names,
	}
	b, err := x509.CreateCertificate(rand.Reader, templ, templ, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("x509.CreateCertificate: %w", err)
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("x509.ParseCertificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{b},
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}

func newFakeConn(in []byte) *fakeConn {
	return &fakeConn{
		Reader: bytes.NewBuffer(in),
		Writer: bytes.NewBuffer(nil),
	}
}

type fakeConn struct {
	io.Reader
	io.Writer
}

func (fakeConn) Close() error {
	return nil
}

func (fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (fakeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (fakeConn) SetDeadline(t time.Time) error {
	return nil
}

func (fakeConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (fakeConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

type testClientHello struct {
	*clientHello

	hpkeCtx *hpke.Sender
}

func newClientHello(opts ...any) *testClientHello {
	h := &testClientHello{
		clientHello: &clientHello{
			LegacyVersion:            0x0303,
			Random:                   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			LegacySessionID:          []byte{1, 2, 3, 4},
			CipherSuite:              []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03},
			LegacyCompressionMethods: []byte{0},
			Extensions:               []extension{},
		},
	}
	var pubKey *ecdh.PublicKey
	var inner *testClientHello
	var config Config
	for _, opt := range opts {
		switch opt {
		case "public":
			h.addServerName("public.example.com")
		case "private":
			h.addServerName("private.example.com")
		case "tls1.3":
			h.addSupportedVersionTLS13()
		case "echExtInner":
			h.addClientHelloExtInner()
		case "ech_outer_extensions":
			h.addECHOuterExt(nil)
		default:
			if c, ok := opt.(Config); ok {
				config = c
			}
			if k, ok := opt.(*ecdh.PublicKey); ok {
				pubKey = k
			}
			if ctx, ok := opt.(*hpke.Sender); ok {
				h.hpkeCtx = ctx
			}
			if i, ok := opt.(*testClientHello); ok {
				inner = i
			}
		}
	}
	if inner != nil {
		info := append([]byte("tls ech\x00"), config...)
		var encap []byte
		if h.hpkeCtx != nil {
			encap = []byte{}
		} else {
			enc, hpkeCtx, err := hpke.SetupSender(hpke.DHKEM_X25519_HKDF_SHA256, 0x0001, 0x0003, pubKey, info)
			if err != nil {
				panic(err)
			}
			h.hpkeCtx = hpkeCtx
			encap = enc
		}
		innerBytes := inner.bytes()[9:]
		h.addClientHelloExtOuter(config[4], encap, make([]byte, len(innerBytes)+16))
		h.parse()
		aad, err := h.marshalAAD()
		if err != nil {
			panic(err)
		}
		payload, err := h.hpkeCtx.Seal(aad, innerBytes)
		if err != nil {
			panic(err)
		}
		h.clientHello.Extensions = h.clientHello.Extensions[:len(h.clientHello.Extensions)-1]
		h.addClientHelloExtOuter(config[4], encap, payload)
	}
	h.parse()
	return h
}

func (h *testClientHello) bytes() []byte {
	m, err := h.Marshal()
	if err != nil {
		panic(err)
	}
	return m
}

func (h *testClientHello) parse() {
	hello, err := parseClientHello(h.bytes()[5:])
	if err != nil {
		panic(err)
	}
	h.clientHello = hello
}

func (h *testClientHello) addServerName(name string) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x00) // name_type
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(name))
		})
	})
	data, err := b.Bytes()
	if err != nil {
		panic(err)
	}
	h.clientHello.Extensions = append(h.clientHello.Extensions, extension{
		0, data,
	})
}

func (h *testClientHello) addSupportedVersionTLS13() {
	h.clientHello.Extensions = append(h.clientHello.Extensions, extension{
		43, []byte{0x02, 0x03, 0x04}, // supported_versions: TLS 1.3
	})
}

func (h *testClientHello) addECHOuterExt(ext []uint16) {
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, e := range ext {
			b.AddUint16(e)
		}
	})
	data, err := b.Bytes()
	if err != nil {
		panic(err)
	}
	h.clientHello.Extensions = append(h.clientHello.Extensions, extension{
		0xfd00, data,
	})
}

func (h *testClientHello) addClientHelloExtInner() {
	h.clientHello.Extensions = append(h.clientHello.Extensions, extension{
		0xfe0d, []byte{0x01},
	})
}

func (h *testClientHello) addClientHelloExtOuter(id uint8, encap, payload []byte) {
	var b cryptobyte.Builder
	b.AddUint8(0x00)
	b.AddUint16(0x0001)
	b.AddUint16(0x0003)
	b.AddUint8(id)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(encap)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(payload)
	})
	data, err := b.Bytes()
	if err != nil {
		panic(err)
	}
	h.clientHello.Extensions = append(h.clientHello.Extensions, extension{
		0xfe0d, data,
	})
}

func helloRetryReq() []byte {
	h := &serverHello{
		LegacyVersion:           0x0303,
		Random:                  slices.Clone(helloRetryRequest),
		LegacySessionID:         []byte{1, 2, 3},
		CipherSuite:             0x0101,
		LegacyCompressionMethod: 0x00,
		Extensions:              nil,
	}
	m, err := h.Marshal()
	if err != nil {
		panic(err)
	}
	return m
}
