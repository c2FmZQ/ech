package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/c2FmZQ/ech"
)

var (
	// https://www.rfc-editor.org/rfc/rfc9180#section-7.1
	kemMap = map[uint16]string{
		0x0000: "Reserved",
		0x0010: "DHKEM(P-256, HKDF-SHA256)",
		0x0011: "DHKEM(P-384, HKDF-SHA384)",
		0x0012: "DHKEM(P-521, HKDF-SHA512)",
		0x0020: "DHKEM(X25519, HKDF-SHA256)",
		0x0021: "DHKEM(X448, HKDF-SHA512)",
	}

	// https://www.rfc-editor.org/rfc/rfc9180#section-7.2
	kdfMap = map[uint16]string{
		0x0000: "Reserved",
		0x0001: "HKDF-SHA256",
		0x0002: "HKDF-SHA384",
		0x0003: "HKDF-SHA512",
	}

	// https://www.rfc-editor.org/rfc/rfc9180#section-7.3
	aeadMap = map[uint16]string{
		0x0000: "Reserved",
		0x0001: "AES-128-GCM",
		0x0002: "AES-256-GCM",
		0x0003: "ChaCha20Poly1305",
		0xFFFF: "Export-only",
	}
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <configlist>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	configList, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil {
		log.Fatalf("ConfigList: %v", err)
	}
	specs, err := ech.ParseConfigList(configList)
	if err != nil {
		log.Fatalf("ConfigList: %v", err)
	}
	for i, c := range specs {
		fmt.Printf("ECHConfig #%d:\n", i+1)
		fmt.Printf("  version: 0x%04x\n", c.Version)
		fmt.Printf("  key_config:\n")
		fmt.Printf("    config_id:  0x%02x\n", c.ID)
		fmt.Printf("    kem_id:     %s (0x%04x)\n", kemMap[c.KEM], c.KEM)
		fmt.Printf("    public_key: 0x%x\n", c.PublicKey)
		fmt.Printf("    cipher_suites:\n")
		for _, cs := range c.CipherSuites {
			fmt.Printf("      - %s (0x%04x), %s (0x%04x)\n", kdfMap[cs.KDF], cs.KDF, aeadMap[cs.AEAD], cs.AEAD)
		}
		fmt.Printf("  maximum_name_length: %d\n", c.MaximumNameLength)
		fmt.Printf("  public_name:         %s\n", c.PublicName)
	}
}
