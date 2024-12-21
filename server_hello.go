package ech

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

type serverHello struct {
	LegacyVersion           uint16
	Random                  []uint8
	LegacySessionID         []byte
	CipherSuite             uint16
	LegacyCompressionMethod uint8
	Extensions              []extension
}

func (h serverHello) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "LegacyVersion: 0x%04x\n", h.LegacyVersion)
	fmt.Fprintf(&b, "Random: 0x%x\n", h.Random)
	fmt.Fprintf(&b, "LegacySessionID: 0x%x\n", h.LegacySessionID)
	fmt.Fprintf(&b, "CipherSuite: 0x%x\n", h.CipherSuite)
	fmt.Fprintf(&b, "LegacyCompressionMethod: 0x%x\n", h.LegacyCompressionMethod)
	fmt.Fprintf(&b, "Extensions:\n")
	for _, ext := range h.Extensions {
		fmt.Fprintf(&b, "  %s(%d): 0x%X (%d bytes)\n", extensionName(ext.Type), ext.Type, ext.Data, len(ext.Data))
	}
	return b.String()
}

func (h serverHello) IsHelloRetryRequest() bool {
	return bytes.Equal(h.Random, helloRetryRequest)
}

func (h *serverHello) Marshal() ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(0x16)
	b.AddUint16(h.LegacyVersion)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x02)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(h.LegacyVersion)
			b.AddBytes(h.Random)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(h.LegacySessionID)
			})
			b.AddUint16(h.CipherSuite)
			b.AddUint8(h.LegacyCompressionMethod)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, ext := range h.Extensions {
					b.AddUint16(ext.Type)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(ext.Data)
					})
				}
			})
		})
	})
	return b.Bytes()
}

func parseServerHello(buf []byte) (*serverHello, error) {
	var hello serverHello

	// https://datatracker.ietf.org/doc/html/rfc8446#section-4
	//
	// struct {
	//    HandshakeType msg_type;    /* handshake type */
	//    uint24 length;             /* remaining bytes in message */
	//      select (Handshake.msg_type) {
	//          case client_hello:          ClientHello;
	//          ...
	//      };
	// } Handshake;
	s := cryptobyte.String(buf)
	var msgType uint8
	if !s.ReadUint8(&msgType) { // msg_type(1)
		return nil, ErrDecodeError
	}
	if msgType != 0x02 { // ServerHello
		return nil, fmt.Errorf("%w: msg_type 0x%x != 0x02", ErrUnexpectedMessage, msgType)
	}
	if !s.Skip(3) { // length(3)
		return nil, ErrDecodeError
	}

	// struct {
	//   ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
	//   Random random;
	//   opaque legacy_session_id_echo<0..32>;
	//   CipherSuite cipher_suite;
	//   uint8 legacy_compression_method = 0;
	//   Extension extensions<6..2^16-1>;
	// } ServerHello;

	if !s.ReadUint16(&hello.LegacyVersion) { // legacy_version
		return nil, ErrDecodeError
	}
	if !s.ReadBytes(&hello.Random, 32) { // random
		return nil, ErrDecodeError
	}

	var v cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&v) { // legacy_session_id
		return nil, ErrDecodeError
	}
	hello.LegacySessionID = slices.Clone(v)
	if !s.ReadUint16(&hello.CipherSuite) { // cipher_suite
		return nil, ErrDecodeError
	}
	if !s.ReadUint8(&hello.LegacyCompressionMethod) { // legacy_compression_method
		return nil, ErrDecodeError
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, ErrDecodeError
	}

	for !extensions.Empty() {
		var extType uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, ErrDecodeError
		}
		hello.Extensions = append(hello.Extensions, extension{
			Type: extType,
			Data: slices.Clone(data),
		})
	}
	return &hello, nil
}
