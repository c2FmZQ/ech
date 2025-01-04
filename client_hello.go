package ech

import (
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// The Client Hello message is specified in RFC 8446 Section 4.1.2
type clientHello struct {
	LegacyVersion            uint16
	Random                   []uint8
	LegacySessionID          []byte
	CipherSuite              []byte
	LegacyCompressionMethods []byte
	Extensions               []extension

	ServerName string
	ALPNProtos []string

	hasECHOuterExtensions bool
	tls13                 bool
	echExt                *echExt
}

// The ECH Extension as specified in Section 5 of
// https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni/.
type echExt struct {
	Type        uint8
	CipherSuite CipherSuite
	ConfigID    uint8
	Enc         []byte
	Payload     []byte
}

func (c clientHello) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "LegacyVersion: 0x%04x\n", c.LegacyVersion)
	fmt.Fprintf(&b, "Random: 0x%x\n", c.Random)
	fmt.Fprintf(&b, "LegacySessionID: 0x%x\n", c.LegacySessionID)
	fmt.Fprintf(&b, "CipherSuite: 0x%x\n", c.CipherSuite)
	fmt.Fprintf(&b, "LegacyCompressionMethods: 0x%x\n", c.LegacyCompressionMethods)
	fmt.Fprintf(&b, "Extensions:\n")
	for _, ext := range c.Extensions {
		fmt.Fprintf(&b, "  %s(%d): 0x%X (%d bytes)\n", extensionName(ext.Type), ext.Type, ext.Data, len(ext.Data))
	}
	if c.echExt != nil {
		fmt.Fprintf(&b, "ECH Type: 0x%02x\n", c.echExt.Type)
		if c.echExt.Type == 0 {
			fmt.Fprintf(&b, "ECH CipherSuite: KDF 0x%04x AEAD 0x%04x\n", c.echExt.CipherSuite.KDF, c.echExt.CipherSuite.AEAD)
			fmt.Fprintf(&b, "ECH ConfigID: 0x%02x\n", c.echExt.ConfigID)
			fmt.Fprintf(&b, "ECH Enc: 0x%x\n", c.echExt.Enc)
			fmt.Fprintf(&b, "ECH Payload: 0x%x\n", c.echExt.Payload)
		}
	}

	return b.String()
}

type extension struct {
	Type uint16
	Data []byte
}

func (c *clientHello) Marshal() ([]byte, error) {
	return c.marshal(false)
}

func (c *clientHello) marshalAAD() ([]byte, error) {
	m, err := c.marshal(true)
	if err != nil {
		return nil, err
	}
	return m[9:], nil
}

func (c *clientHello) marshal(aad bool) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(0x16)
	b.AddUint16(c.LegacyVersion)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x01)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(c.LegacyVersion)
			b.AddBytes(c.Random)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(c.LegacySessionID)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(c.CipherSuite)
			})
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(c.LegacyCompressionMethods)
			})

			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, ext := range c.Extensions {
					b.AddUint16(ext.Type)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						if aad && ext.Type == 0xfe0d {
							n := len(ext.Data) - len(c.echExt.Payload)
							b.AddBytes(ext.Data[:n])
							b.AddBytes(make([]byte, len(ext.Data[n:])))
							return
						}
						b.AddBytes(ext.Data)
					})
				}
			})
		})
	})
	return b.Bytes()
}

func parseClientHello(buf []byte) (*clientHello, error) {
	hello := new(clientHello)

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
	if msgType != 0x01 { // ClientHello
		return nil, fmt.Errorf("%w: msg_type 0x%x != 0x01", ErrUnexpectedMessage, msgType)
	}
	var ss cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&ss) {
		return nil, ErrDecodeError
	}
	zeros := s
	s = ss

	// https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
	// ClientHello
	//   uint16 ProtocolVersion;
	//   opaque Random[32];
	//
	//   uint8 CipherSuite[2];    /* Cryptographic suite selector */
	//
	//   struct {
	//     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
	//     Random random;
	//     opaque legacy_session_id<0..32>;
	//     CipherSuite cipher_suites<2..2^16-2>;
	//     opaque legacy_compression_methods<1..2^8-1>;
	//     Extension extensions<8..2^16-1>;
	//   } ClientHello;
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
	if !s.ReadUint16LengthPrefixed(&v) { // cipher_suites
		return nil, ErrDecodeError
	}
	hello.CipherSuite = slices.Clone(v)
	if !s.ReadUint8LengthPrefixed(&v) { // legacy_compression_methods
		return nil, ErrDecodeError
	}
	hello.LegacyCompressionMethods = slices.Clone(v)
	//if len(hello.LegacyCompressionMethods) != 1 || hello.LegacyCompressionMethods[0] != 0x0 {
	//	return nil, ErrIllegalParameter
	//}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, ErrDecodeError
	}

	// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2
	// Extensions
	//
	// struct {
	//     ExtensionType extension_type;
	//     opaque extension_data<0..2^16-1>;
	// } Extension;
	//
	// enum {
	//     server_name(0),                             /* RFC 6066 */
	//     ...
	//     application_layer_protocol_negotiation(16), /* RFC 7301 */
	//     ...
	// } ExtensionType;

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
	if err := hello.parseExtensions(); err != nil {
		return nil, err
	}
	if hello.echExt != nil && hello.echExt.Type == 1 {
		for _, p := range zeros {
			if p != 0 {
				return nil, ErrIllegalParameter
			}
		}
	}
	return hello, nil
}

func (c *clientHello) parseExtensions() error {
	c.ServerName = ""
	c.ALPNProtos = nil
	c.hasECHOuterExtensions = false
	c.tls13 = false
	c.echExt = nil

	for _, ext := range c.Extensions {
		data := cryptobyte.String(ext.Data)
		switch ext.Type {
		case 0:
			// https://datatracker.ietf.org/doc/html/rfc6066#section-3
			// Server Name Indication
			//
			// struct {
			//   NameType name_type;
			//   select (name_type) {
			//       case host_name: HostName;
			//   } name;
			// } ServerName;
			//
			// enum {
			//   host_name(0), (255)
			// } NameType;
			//
			// opaque HostName<1..2^16-1>;
			//
			// struct {
			//   ServerName server_name_list<1..2^16-1>
			// } ServerNameList;

			var serverNameList cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&serverNameList) {
				return fmt.Errorf("%w: serverNameList", ErrDecodeError)
			}
			for !serverNameList.Empty() {
				var nameType uint8
				var hostName cryptobyte.String
				if !serverNameList.ReadUint8(&nameType) {
					return fmt.Errorf("%w: name type", ErrDecodeError)
				}
				if nameType != 0 { // host name
					return fmt.Errorf("%w: invalid nametype 0x%x", ErrIllegalParameter, nameType)
				}
				if !serverNameList.ReadUint16LengthPrefixed(&hostName) || c.ServerName != "" {
					return fmt.Errorf("%w: host name", ErrDecodeError)
				}
				c.ServerName = string(hostName)
			}
		case 16:
			// https://datatracker.ietf.org/doc/html/rfc7301#section-3
			// Application-Layer Protocol Negotiation
			//
			//  enum {
			//      application_layer_protocol_negotiation(16), (65535)
			//  } ExtensionType;
			//
			//  The "extension_data" field of the
			//  ("application_layer_protocol_negotiation(16)") extension SHALL
			//  contain a "ProtocolNameList" value.
			//
			//  opaque ProtocolName<1..2^8-1>;
			//
			//  struct {
			//      ProtocolName protocol_name_list<2..2^16-1>
			//  } ProtocolNameList;
			var protocolNameList cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&protocolNameList) {
				return fmt.Errorf("%w: protocol name list", ErrDecodeError)
			}
			for !protocolNameList.Empty() {
				var protocolName cryptobyte.String
				if !protocolNameList.ReadUint8LengthPrefixed(&protocolName) {
					return fmt.Errorf("%w: protocol name", ErrDecodeError)
				}
				c.ALPNProtos = append(c.ALPNProtos, string(protocolName))
			}

		case 43:
			// struct {
			//   select (Handshake.msg_type) {
			//     case client_hello:
			//       ProtocolVersion versions<2..254>;
			//     case server_hello: /* and HelloRetryRequest */
			//       ProtocolVersion selected_version;
			//   };
			// } SupportedVersions;
			var versions cryptobyte.String
			if !data.ReadUint8LengthPrefixed(&versions) {
				return fmt.Errorf("%w: supported versions", ErrDecodeError)
			}
			for !versions.Empty() {
				var v uint16
				if !versions.ReadUint16(&v) {
					return fmt.Errorf("%w: version", ErrDecodeError)
				}
				if v >= 0x0304 {
					c.tls13 = true
				}
			}

		case 0xfd00:
			c.hasECHOuterExtensions = true

		case 0xfe0d:
			// https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni/
			// 5.  The "encrypted_client_hello" Extension
			//
			// enum {
			//   encrypted_client_hello(0xfe0d), (65535)
			//  } ExtensionType;
			// enum { outer(0), inner(1) } ECHClientHelloType;
			//
			//        struct {
			//           ECHClientHelloType type;
			//           select (ECHClientHello.type) {
			//               case outer:
			//                   HpkeSymmetricCipherSuite cipher_suite;
			//                   uint8 config_id;
			//                   opaque enc<0..2^16-1>;
			//                   opaque payload<1..2^16-1>;
			//               case inner:
			//                   Empty;
			//           };
			//        } ECHClientHello;
			c.echExt = &echExt{}

			if !data.ReadUint8(&c.echExt.Type) { // type
				return fmt.Errorf("%w: ech type", ErrDecodeError)
			}
			// Section 7
			// If ECHClientHello.type is not a valid ECHClientHelloType, then the
			// server MUST abort with an "illegal_parameter" alert.
			if c.echExt.Type > 1 {
				return fmt.Errorf("%w: ech type %d", ErrIllegalParameter, c.echExt.Type)
			}
			if c.echExt.Type == 0 { // Outer
				if !data.ReadUint16(&c.echExt.CipherSuite.KDF) { // cipher_suite.kdf
					return fmt.Errorf("%w: ech ext kdf", ErrDecodeError)
				}
				if !data.ReadUint16(&c.echExt.CipherSuite.AEAD) { // cipher_suite.aead
					return fmt.Errorf("%w: ech ext aead", ErrDecodeError)
				}
				if !data.ReadUint8(&c.echExt.ConfigID) { // config_id
					return fmt.Errorf("%w: ech ext config id", ErrDecodeError)
				}
				var v cryptobyte.String
				if !data.ReadUint16LengthPrefixed(&v) { // enc
					return fmt.Errorf("%w: ech ext enc", ErrDecodeError)
				}
				c.echExt.Enc = slices.Clone(v)
				if !data.ReadUint16LengthPrefixed(&v) { // payload
					return fmt.Errorf("%w: ech ext payload", ErrDecodeError)
				}
				c.echExt.Payload = slices.Clone(v)
			}
		}
	}
	return nil
}
