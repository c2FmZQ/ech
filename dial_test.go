package ech

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/url"
	"testing"

	"github.com/c2FmZQ/ech/dns"
)

func TestDial(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	configList, err := ConfigList([]Config{config})
	if err != nil {
		t.Fatalf("ConfigList: %v", err)
	}

	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)

	tlsCert, err := newCert("example.com")
	if err != nil {
		t.Fatalf("newCert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(tlsCert.Leaf)

	dnsServer := startTestDNSServer(t, []dns.RR{{
		Name: "example.com", Type: 65, Class: 1, TTL: 60,
		Data: dns.HTTPS{Priority: 1, Port: uint16(addr.Port), IPv4Hint: []net.IP{addr.IP}, ECH: configList},
	}})
	defer dnsServer.Close()
	saveResolver := defaultResolver
	defaultResolver = &Resolver{baseURL: url.URL{Scheme: "http", Host: dnsServer.Listener.Addr().String(), Path: "/dns-query"}}
	defer func() {
		defaultResolver = saveResolver
	}()

	go func() {
		serverConn, err := ln.Accept()
		if err != nil {
			if err != net.ErrClosed {
				t.Errorf("ln.Accept: %v", err)
			}
			return
		}
		defer serverConn.Close()
		outConn, err := NewConn(t.Context(), serverConn, WithKeys([]Key{{
			Config:      config,
			PrivateKey:  privKey.Bytes(),
			SendAsRetry: true,
		}}))
		if err != nil {
			t.Errorf("NewConn: %v", err)
			return
		}
		if !outConn.ECHAccepted() {
			t.Errorf("Server ECHAccepted is false")
		}
		server := tls.Server(outConn, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		})
		if _, err := server.Write([]byte("Hello!\n")); err != nil {
			t.Errorf("server.Write: %v", err)
			return
		}
	}()

	client, err := Dial(t.Context(), "tcp", "example.com", &tls.Config{
		ServerName:                     "example.com",
		RootCAs:                        rootCAs,
		NextProtos:                     []string{"h2", "http/1.1"},
		EncryptedClientHelloConfigList: nil, // Should come from DNS
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	b, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if got, want := string(b), "Hello!\n"; got != want {
		t.Errorf("Got %q, want %q", got, want)
	}
	if !client.ConnectionState().ECHAccepted {
		t.Errorf("Client ECHAccepted is false")
	}
}
