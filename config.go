package ech

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// Config is a serialized ECH Config.
type Config []byte

type Key = tls.EncryptedClientHelloKey

/*
type Key struct {
	Config      Config
	PrivateKey  []byte
	SendAsRetry bool
}
*/

// Config returns a serialized ECH ConfigList.
func ConfigList(configs []Config) ([]byte, error) {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, cfg := range configs {
			c.AddBytes(cfg)
		}
	})
	return b.Bytes()
}

// NewConfig generates an ECH Config and a private key. It currently supports
// only DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
func NewConfig(id uint8, publicName []byte) (*ecdh.PrivateKey, Config, error) {
	if l := len(publicName); l == 0 || l > 255 {
		return nil, nil, errors.New("invalid public name length")
	}

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(0xfe0d) // version
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(id)      // config_id
		b.AddUint16(0x0020) // kem_id:  DHKEM_X25519_HKDF_SHA256
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(privKey.PublicKey().Bytes()) // public_key
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // cipher_suites
			b.AddUint16(0x0001) // KDF_HKDF_SHA256
			b.AddUint16(0x0003) // AEAD_ChaCha20Poly1305
		})
		b.AddUint8(uint8(min(len(publicName)+16, 255))) // maximum_name_length
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(publicName) // public_name
		})
		b.AddUint16(0) // extensions
	})

	conf, err := b.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return privKey, conf, nil
}

type config struct {
	Version           uint16
	ID                uint8
	KEMID             uint16
	PublicKey         cryptobyte.String
	CipherSuites      []cipherSuite
	MinimumNameLength uint8
	PublicName        cryptobyte.String
}

type cipherSuite struct {
	KDF  uint16
	AEAD uint16
}

func parseConfig(cfg []byte) (config, error) {
	var out config
	s := cryptobyte.String(cfg)
	if !s.ReadUint16(&out.Version) {
		return out, ErrDecodeError
	}
	var ss cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&ss) {
		return out, ErrDecodeError
	}
	s = ss
	if !s.ReadUint8(&out.ID) {
		return out, ErrDecodeError
	}
	if !s.ReadUint16(&out.KEMID) {
		return out, ErrDecodeError
	}
	if !s.ReadUint16LengthPrefixed(&out.PublicKey) {
		return out, ErrDecodeError
	}
	var cs cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cs) {
		return out, ErrDecodeError
	}
	for !cs.Empty() {
		var suite cipherSuite
		if !cs.ReadUint16(&suite.KDF) {
			return out, ErrDecodeError
		}
		if !cs.ReadUint16(&suite.AEAD) {
			return out, ErrDecodeError
		}
		out.CipherSuites = append(out.CipherSuites, suite)
	}
	if !s.ReadUint8(&out.MinimumNameLength) {
		return out, ErrDecodeError
	}
	if !s.ReadUint8LengthPrefixed(&out.PublicName) {
		return out, ErrDecodeError
	}
	return out, nil
}
