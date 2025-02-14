// This is an example of a client using [ech.Dial] to connect to a TLS server
// using Encrypted Client Hello (ECH).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"os"

	"github.com/c2FmZQ/ech"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "The TCP address of the server.")
	serverName := flag.String("server-name", "public.example.com", "The server name to use.")
	base64ConfigList := flag.String("config-list", "", "The ECH ConfigList to use, base64-encoded.")
	base64ServerCert := flag.String("server-cert", "", "The server certificate, base64-encoded.")
	flag.Parse()

	tlsConfig := &tls.Config{
		ServerName:         *serverName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1", "foo"},
	}
	if *base64ConfigList != "" {
		configList, err := base64.StdEncoding.DecodeString(*base64ConfigList)
		if err != nil {
			log.Fatalf("ConfigList: %v", err)
		}
		tlsConfig.EncryptedClientHelloConfigList = configList
	}
	if *base64ServerCert != "" {
		serverCert, err := base64.StdEncoding.DecodeString(*base64ServerCert)
		if err != nil {
			log.Panicf("ServerCert: %v", err)
		}
		cert, err := x509.ParseCertificate(serverCert)
		if err != nil {
			log.Panicf("ServerCert: %v", err)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		tlsConfig.RootCAs.AddCert(cert)
	}
	client, err := ech.Dial(context.Background(), "tcp", *addr, tlsConfig)
	if err != nil {
		log.Fatalf("ech.Dial: %v", err)
	}
	defer client.Close()
	log.Printf("Connected to %s", client.RemoteAddr())
	log.Printf("ECH Accepted: %v", client.ConnectionState().ECHAccepted)

	if _, err := io.Copy(os.Stdout, client); err != nil {
		log.Printf("Error: %v", err)
	}
}
