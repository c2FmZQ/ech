package ech

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/c2FmZQ/ech/dns"
	"github.com/c2FmZQ/ech/testutil"
)

func TestTransport(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("public.example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	configList, err := ConfigList([]Config{config})
	if err != nil {
		t.Fatalf("ConfigList: %v", err)
	}
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)

	tlsCert, err := testutil.NewCert("public.example.com", "private.example.com")
	if err != nil {
		t.Fatalf("NewCert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(tlsCert.Leaf)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()
			if req.TLS == nil {
				http.Error(w, "not TLS", http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, "%s %s: ECHAccepted:%v\n", req.Method, req.RequestURI, req.TLS.ECHAccepted)
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{"h2"},
			EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
				Config:      config,
				PrivateKey:  privKey.Bytes(),
				SendAsRetry: true,
			}},
		},
	}
	go server.ServeTLS(ln, "", "")

	dnsServer := testutil.StartTestDNSServer(t, []dns.RR{{
		Name: "private.example.com", Type: 65, Class: 1, TTL: 60,
		Data: dns.HTTPS{Priority: 1, Port: uint16(addr.Port), ECH: configList},
	}, {
		Name: "private.example.com", Type: 1, Class: 1, TTL: 60,
		Data: addr.IP,
	}})
	defer dnsServer.Close()

	transport := NewTransport()
	transport.Dialer.RequireECH = true
	transport.Resolver = &Resolver{baseURL: url.URL{Scheme: "http", Host: dnsServer.Listener.Addr().String(), Path: "/dns-query"}}
	transport.TLSConfig = &tls.Config{
		RootCAs:                        rootCAs,
		EncryptedClientHelloConfigList: configList,
	}

	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://private.example.com/foo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if got, want := resp.StatusCode, 200; got != want {
		t.Errorf("StatusCode = %d, want %d", got, want)
	}
	if got, want := string(body), "GET /foo: ECHAccepted:true\n"; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
	if got, want := resp.TLS.ECHAccepted, true; got != want {
		t.Errorf("ECHAccepted = %v, want %v", got, want)
	}
}

func TestTransportTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			defer req.Body.Close()
			fmt.Fprintf(w, "%s %s: Plaintext HTTP\n", req.Method, req.RequestURI)
		}),
	}
	go server.Serve(ln)

	dnsServer := testutil.StartTestDNSServer(t, []dns.RR{{
		Name: "private.example.com", Type: 65, Class: 1, TTL: 60,
		Data: dns.HTTPS{Priority: 1, Port: uint16(addr.Port)},
	}, {
		Name: "private.example.com", Type: 1, Class: 1, TTL: 60,
		Data: addr.IP,
	}})
	defer dnsServer.Close()

	transport := NewTransport()
	transport.Dialer.RequireECH = true
	transport.Resolver = &Resolver{baseURL: url.URL{Scheme: "http", Host: dnsServer.Listener.Addr().String(), Path: "/dns-query"}}

	client := &http.Client{Transport: transport}

	url := fmt.Sprintf("http://private.example.com:%d/foo", addr.Port)

	if _, err := client.Get(url); err == nil || !strings.Contains(err.Error(), "unable to use ECH with plaintext HTTP") {
		t.Fatalf("GET should have failed. err=%v", err)
	}
	transport.Dialer.RequireECH = false
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if got, want := resp.StatusCode, 200; got != want {
		t.Errorf("StatusCode = %d, want %d", got, want)
	}
	if got, want := string(body), "GET /foo: Plaintext HTTP\n"; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
}
