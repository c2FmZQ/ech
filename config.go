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

// NewConfig generates an ECH Config and a private key.
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
		b.AddUint8(0) // maximum_name_length
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
