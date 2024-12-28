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
	c := ConfigSpec{
		Version:   0xfe0d,
		ID:        id,
		KEM:       0x0020, // DHKEM_X25519_HKDF_SHA256
		PublicKey: privKey.PublicKey().Bytes(),
		CipherSuites: []CipherSuite{{
			KDF:  0x0001, // KDF_HKDF_SHA256
			AEAD: 0x0003, // AEAD_ChaCha20Poly1305
		}},
		MinimumNameLength: uint8(min(len(publicName)+16, 255)),
		PublicName:        publicName,
	}
	conf, err := c.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return privKey, conf, nil
}

// Spec returns the structured version of cfg.
func (cfg Config) Spec() (ConfigSpec, error) {
	var out ConfigSpec
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
	if !s.ReadUint16(&out.KEM) {
		return out, ErrDecodeError
	}
	if !s.ReadUint16LengthPrefixed((*cryptobyte.String)(&out.PublicKey)) {
		return out, ErrDecodeError
	}
	var cs cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cs) {
		return out, ErrDecodeError
	}
	for !cs.Empty() {
		var suite CipherSuite
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
	if !s.ReadUint8LengthPrefixed((*cryptobyte.String)(&out.PublicName)) {
		return out, ErrDecodeError
	}
	return out, nil
}

// ConfigSpec represents an ECH Config. It is specified in Section 4 of
// https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
type ConfigSpec struct {
	Version           uint16
	ID                uint8
	KEM               uint16
	PublicKey         []byte
	CipherSuites      []CipherSuite
	MinimumNameLength uint8
	PublicName        []byte
}

type CipherSuite struct {
	KDF  uint16
	AEAD uint16
}

// Bytes returns the serialized version of the ECH Config.
func (c ConfigSpec) Bytes() (Config, error) {
	if l := len(c.PublicName); l == 0 || l > 255 {
		return nil, errors.New("invalid public name length")
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(c.Version)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(c.ID)
		b.AddUint16(c.KEM)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(c.PublicKey)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, cs := range c.CipherSuites {
				b.AddUint16(cs.KDF)
				b.AddUint16(cs.AEAD)
			}
		})
		b.AddUint8(uint8(min(len(c.PublicName)+16, 255)))
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(c.PublicName)
		})
		b.AddUint16(0) // extensions
	})
	conf, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return conf, nil
}
