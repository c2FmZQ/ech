package ech

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

type serverHello struct {
	MsgType uint8
	Length  uint32

	LegacyVersion           uint16
	Random                  []uint8
	LegacySessionID         []byte
	CipherSuite             uint16
	LegacyCompressionMethod uint8

	Extensions []helloExtension
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
	if !s.ReadUint8(&hello.MsgType) { // msg_type(1)
		return nil, ErrInvalidFormat
	}
	if hello.MsgType != 0x02 { // ServerHello
		return nil, fmt.Errorf("%w: msg_type 0x%x != 0x02", ErrUnexpectedMessage, hello.MsgType)
	}
	var hlength []byte
	if !s.ReadBytes(&hlength, 3) { // length(3)
		return nil, ErrInvalidFormat
	}
	hello.Length = uint32(hlength[0])<<16 | uint32(hlength[1])<<8 | uint32(hlength[2])

	// struct {
	//   ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
	//   Random random;
	//   opaque legacy_session_id_echo<0..32>;
	//   CipherSuite cipher_suite;
	//   uint8 legacy_compression_method = 0;
	//   Extension extensions<6..2^16-1>;
	// } ServerHello;

	if !s.ReadUint16(&hello.LegacyVersion) { // legacy_version
		return nil, ErrInvalidFormat
	}
	if !s.ReadBytes(&hello.Random, 32) { // random
		return nil, ErrInvalidFormat
	}

	var v cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&v) { // legacy_session_id
		return nil, ErrInvalidFormat
	}
	hello.LegacySessionID = slices.Clone(v)
	if !s.ReadUint16(&hello.CipherSuite) { // cipher_suite
		return nil, ErrInvalidFormat
	}
	if !s.ReadUint8(&hello.LegacyCompressionMethod) { // legacy_compression_method
		return nil, ErrInvalidFormat
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, ErrInvalidFormat
	}

	for !extensions.Empty() {
		var extType uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, ErrInvalidFormat
		}
		hello.Extensions = append(hello.Extensions, helloExtension{
			Type: extType,
			Data: slices.Clone(data),
		})
	}
	return &hello, nil
}
