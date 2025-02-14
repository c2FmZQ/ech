// This is an example of a Client-Facing Server using ech.Conn to handle the
// TLS Encrypted Client Hello (ECH) message and routing the connection using the
// encrypting Server Name Indication (SNI).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/c2FmZQ/ech"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "The TCP address to use.")
	publicName := flag.String("public-name", "public.example.com", "The public name to use.")
	flag.Parse()

	privKey, config, err := ech.NewConfig(1, []byte(*publicName))
	if err != nil {
		log.Fatalf("NewConfig: %v", err)
	}
	privKeyBytes := privKey.Bytes()
	configList, err := ech.ConfigList([]ech.Config{config})
	if err != nil {
		log.Fatalf("ConfigList: %v", err)
	}
	log.Printf("ConfigList: %s", base64.StdEncoding.EncodeToString(configList))

	tlsCert, err := newCert(*publicName)
	if err != nil {
		log.Fatalf("newCert: %v", err)
	}
	log.Printf("Server Cert: %s", base64.StdEncoding.EncodeToString(tlsCert.Leaf.Raw))

	echKeys := []tls.EncryptedClientHelloKey{{
		Config:      config,
		PrivateKey:  privKeyBytes,
		SendAsRetry: true,
	}}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	log.Printf("Accepting connections on %s", ln.Addr().String())

	for {
		serverConn, err := ln.Accept()
		if err != nil {
			log.Fatalf("ln.Accept: %v", err)
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := ech.NewConn(ctx, serverConn, ech.WithKeys(echKeys))
			if err != nil {
				log.Printf("NewConn: %v", err)
				return
			}
			log.Printf("ServerName: %s", conn.ServerName())
			log.Printf("ALPNProtos: %s", conn.ALPNProtos())

			switch host := conn.ServerName(); host {
			case *publicName:
				server := tls.Server(conn, &tls.Config{
					Certificates:             []tls.Certificate{tlsCert},
					EncryptedClientHelloKeys: echKeys,
				})
				fmt.Fprintf(server, "Hello, this is %s\n", *publicName)
				fmt.Fprintf(server, "ServerName: %s\n", conn.ServerName())
				fmt.Fprintf(server, "ALPNProtos: %s\n", conn.ALPNProtos())
				fmt.Fprintf(server, "ECHPresented: %v\n", conn.ECHPresented())
				fmt.Fprintf(server, "ECHAccepted: %v\n", conn.ECHAccepted())
				server.Close()

			default:
				server := tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{tlsCert},
				})
				fmt.Fprintf(server, "Hello, this is a private server\n")
				fmt.Fprintf(server, "ServerName: %s\n", conn.ServerName())
				fmt.Fprintf(server, "ALPNProtos: %s\n", conn.ALPNProtos())
				fmt.Fprintf(server, "ECHPresented: %v\n", conn.ECHPresented())
				fmt.Fprintf(server, "ECHAccepted: %v\n", conn.ECHAccepted())
				server.Close()
			}
		}()
	}
}

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
