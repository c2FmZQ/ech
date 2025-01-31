package ech

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"testing"

	"github.com/c2FmZQ/ech/dns"
	"github.com/c2FmZQ/ech/testutil"
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
	_, config2, err := NewConfig(1, []byte("example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	configList2, err := ConfigList([]Config{config2})
	if err != nil {
		t.Fatalf("ConfigList: %v", err)
	}

	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	port := addr.Port

	tlsCert, err := testutil.NewCert(
		"example.com",
		"h1.example.com",
		"h2.example.com",
		"h3.example.com",
	)
	if err != nil {
		t.Fatalf("NewCert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(tlsCert.Leaf)

	dnsServer := testutil.StartTestDNSServer(t, []dns.RR{{
		Name: "h1.example.com", Type: 65, Class: 1, TTL: 60,
		Data: dns.HTTPS{Priority: 1, Port: uint16(addr.Port), IPv4Hint: []net.IP{addr.IP}, ECH: configList},
	}, {
		Name: "h2.example.com", Type: 65, Class: 1, TTL: 60,
		Data: dns.HTTPS{Priority: 1, Port: uint16(addr.Port), IPv4Hint: []net.IP{addr.IP}, ECH: configList2},
	}, {
		Name: "h3.example.com", Type: 1, Class: 1, TTL: 60,
		Data: addr.IP,
	}})
	defer dnsServer.Close()
	saveResolver := DefaultResolver
	DefaultResolver = &Resolver{baseURL: url.URL{Scheme: "http", Host: dnsServer.Listener.Addr().String(), Path: "/dns-query"}}
	defer func() {
		DefaultResolver = saveResolver
	}()

	go func() {
		for {
			serverConn, err := ln.Accept()
			if err != nil {
				t.Logf("Listener closed: %v", err)
				return
			}
			go func() {
				defer serverConn.Close()
				keys := []Key{{
					Config:      config,
					PrivateKey:  privKey.Bytes(),
					SendAsRetry: true,
				}}
				outConn, err := NewConn(t.Context(), serverConn, WithKeys(keys))
				if err != nil {
					t.Errorf("NewConn: %v", err)
					return
				}
				server := tls.Server(outConn, &tls.Config{
					Certificates:             []tls.Certificate{tlsCert},
					EncryptedClientHelloKeys: keys,
				})
				if _, err := server.Write([]byte("Hello!\n")); err != nil {
					t.Errorf("server.Write: %v", err)
					return
				}
			}()
		}
	}()

	for _, tc := range []struct {
		host       string
		port       int
		configList []byte
	}{
		{"h1.example.com", 443, nil},          // port & config list from DNS
		{"h2.example.com", 443, nil},          // port & config list from DNS (retry)
		{"h3.example.com", port, configList},  // correct config list
		{"h3.example.com", port, configList2}, // incorrect config list (retry)
	} {
		target := fmt.Sprintf("%s:%d", tc.host, tc.port)
		client, err := Dial(t.Context(), "tcp", target, &tls.Config{
			ServerName:                     tc.host,
			RootCAs:                        rootCAs,
			NextProtos:                     []string{"h2", "http/1.1"},
			EncryptedClientHelloConfigList: tc.configList,
		})
		if err != nil {
			t.Fatalf("[%s] Dial: %v", tc.host, err)
		}
		defer client.Close()
		b, err := io.ReadAll(client)
		if err != nil {
			t.Fatalf("[%s] Body: %v", tc.host, err)
		}
		if got, want := string(b), "Hello!\n"; got != want {
			t.Errorf("[%s] Got %q, want %q", tc.host, got, want)
		}
		if !client.ConnectionState().ECHAccepted {
			t.Errorf("[%s] Client ECHAccepted is false", tc.host)
		}
	}
}
