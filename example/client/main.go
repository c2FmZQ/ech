package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	addr := flag.String("addr", "localhost:8443", "The TCP address of the server.")
	serverName := flag.String("server-name", "public.example.com", "The server name to use.")
	base64ConfigList := flag.String("config-list", "", "The ECH ConfigList to use, base64-encoded.")
	base64ServerCert := flag.String("server-cert", "", "The server certificate, base64-encoded.")
	flag.Parse()

	clientConn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatalf("net.Dial: %v", err)
	}
	log.Printf("Connected to %s", clientConn.RemoteAddr())
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
	client := tls.Client(clientConn, tlsConfig)
	defer client.Close()
	if err := client.Handshake(); err != nil {
		var echErr *tls.ECHRejectionError
		if errors.As(err, &echErr) {
			log.Fatalf("Server has new ECH ConfigList: %s", base64.StdEncoding.EncodeToString(echErr.RetryConfigList))
		}
		log.Fatalf("Error: %v", err)
	}
	log.Printf("ECH Accepted: %v", client.ConnectionState().ECHAccepted)

	if _, err := io.Copy(os.Stdout, client); err != nil {
		log.Printf("Error: %v", err)
	}
}
