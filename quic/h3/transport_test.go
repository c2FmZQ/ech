package h3

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/c2FmZQ/ech"
	"github.com/c2FmZQ/ech/dns"
	"github.com/c2FmZQ/ech/testutil"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestNewTransport(t *testing.T) {
	privKey, config, err := ech.NewConfig(1, []byte("public.example.com"))
	if err != nil {
		t.Fatalf("ech.NewConfig: %v", err)
	}
	configList, err := ech.ConfigList([]ech.Config{config})
	if err != nil {
		t.Fatalf("ech.ConfigList: %v", err)
	}

	tlsCert, err := testutil.NewCert("public.example.com", "private.example.com", "private2.example.com")
	if err != nil {
		t.Fatalf("NewCert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(tlsCert.Leaf)

	udpln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}})
	if err != nil {
		t.Fatalf("net.ListenUDP: %v", err)
	}
	defer udpln.Close()

	udpAddr := udpln.LocalAddr().(*net.UDPAddr)

	qln, err := quic.Listen(udpln, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h3"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config:      config,
			PrivateKey:  privKey.Bytes(),
			SendAsRetry: true,
		}},
	}, nil)
	if err != nil {
		t.Fatalf("quic.Listen: %v", err)
	}

	go func() {
		server := &http3.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				defer req.Body.Close()
				if req.TLS == nil {
					http.Error(w, "not TLS", http.StatusBadRequest)
					return
				}
				fmt.Fprintf(w, "H3 %s %s: ECHAccepted:%v\n", req.Method, req.RequestURI, req.TLS.ECHAccepted)
			}),
		}

		for {
			conn, err := qln.Accept(t.Context())
			if err != nil {
				return
			}
			server.ServeQUICConn(conn)
		}
	}()

	tcpln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer tcpln.Close()

	tcpAddr := tcpln.Addr().(*net.TCPAddr)

	go func() {
		server := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				defer req.Body.Close()
				if req.TLS == nil {
					http.Error(w, "not TLS", http.StatusBadRequest)
					return
				}
				fmt.Fprintf(w, "H2 %s %s: ECHAccepted:%v\n", req.Method, req.RequestURI, req.TLS.ECHAccepted)
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
		server.ServeTLS(tcpln, "", "")
	}()

	dnsServer := testutil.StartTestDNSServer(t, []dns.RR{{
		Name: "private.example.com", Type: 65, Class: 1, TTL: 60,
		Data: dns.HTTPS{Priority: 1, Port: uint16(udpAddr.Port), ALPN: []string{"h3"}, NoDefaultALPN: true, ECH: configList},
	}, {
		Name: "private.example.com", Type: 1, Class: 1, TTL: 60,
		Data: udpAddr.IP,
	}, {
		Name: "private2.example.com", Type: 65, Class: 1, TTL: 60,
		Data: dns.HTTPS{Priority: 1, Port: uint16(tcpAddr.Port), ALPN: []string{"h2"}, NoDefaultALPN: true, ECH: configList},
	}, {
		Name: "private2.example.com", Type: 1, Class: 1, TTL: 60,
		Data: udpAddr.IP,
	}})
	defer dnsServer.Close()

	transport := NewTransport(nil)
	transport.Dialer.RequireECH = true
	resolver, err := ech.NewResolver(fmt.Sprintf("http://%s/dns-query", dnsServer.Listener.Addr()))
	if err != nil {
		t.Fatalf("ech.NewResolver: %v", err)
	}
	transport.Resolver = resolver
	transport.TLSConfig = &tls.Config{
		RootCAs:                        rootCAs,
		EncryptedClientHelloConfigList: configList,
		NextProtos:                     []string{"h3", "h2"},
	}

	client := &http.Client{Transport: transport}

	t.Run("H3", func(t *testing.T) {
		resp, err := client.Get("https://private.example.com/foo")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if got, want := resp.StatusCode, 200; got != want {
			t.Errorf("StatusCode = %d, want %d", got, want)
		}
		if got, want := string(body), "H3 GET /foo: ECHAccepted:true\n"; got != want {
			t.Errorf("Body = %q, want %q", got, want)
		}
		if got, want := resp.TLS.ECHAccepted, true; got != want {
			t.Errorf("ECHAccepted = %v, want %v", got, want)
		}
	})

	t.Run("H2", func(t *testing.T) {
		resp, err := client.Get("https://private2.example.com/foo")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if got, want := resp.StatusCode, 200; got != want {
			t.Errorf("StatusCode = %d, want %d", got, want)
		}
		if got, want := string(body), "H2 GET /foo: ECHAccepted:true\n"; got != want {
			t.Errorf("Body = %q, want %q", got, want)
		}
		if got, want := resp.TLS.ECHAccepted, true; got != want {
			t.Errorf("ECHAccepted = %v, want %v", got, want)
		}
	})
}
