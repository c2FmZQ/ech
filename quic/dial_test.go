package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/c2FmZQ/ech"
	"github.com/c2FmZQ/ech/dns"
	"github.com/c2FmZQ/ech/testutil"
	"github.com/quic-go/quic-go"
)

func TestDial(t *testing.T) {
	privKey, config, err := ech.NewConfig(1, []byte("example.com"))
	if err != nil {
		t.Fatalf("ech.NewConfig: %v", err)
	}
	configList, err := ech.ConfigList([]ech.Config{config})
	if err != nil {
		t.Fatalf("ConfigList: %v", err)
	}

	tlsCert, err := testutil.NewCert("example.com")
	if err != nil {
		t.Fatalf("NewCert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(tlsCert.Leaf)

	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"foo"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config:      config,
			PrivateKey:  privKey.Bytes(),
			SendAsRetry: true,
		}},
	}, nil)
	if err != nil {
		t.Fatalf("quic.ListenAddr: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.UDPAddr)

	dnsServer := testutil.StartTestDNSServer(t, []dns.RR{{
		Name: "example.com", Type: 65, Class: 1, TTL: 60,
		Data: dns.HTTPS{Priority: 1, Port: uint16(addr.Port), IPv4Hint: []net.IP{addr.IP}, ECH: configList},
	}})
	defer dnsServer.Close()
	res, err := ech.NewResolver("http://" + dnsServer.Listener.Addr().String() + "/dns-query")
	if err != nil {
		t.Fatalf("ech.NewResolver: %v", err)
	}
	saveResolver := ech.DefaultResolver
	ech.DefaultResolver = res
	defer func() {
		ech.DefaultResolver = saveResolver
	}()

	go func() {
		ctx := t.Context()
		for {
			server, err := ln.Accept(ctx)
			if err != nil {
				if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, context.Canceled) {
					break
				}
				t.Logf("Server Accept: %v", err)
				continue
			}
			t.Logf("Server received connection from %s", server.RemoteAddr())
			if !server.ConnectionState().TLS.ECHAccepted {
				t.Errorf("Server ECHAccepted is false")
			}
			go func() {
				stream, err := server.AcceptStream(ctx)
				if err != nil {
					server.CloseWithError(0x11, err.Error())
					return
				}
				t.Logf("Server accepted stream from %s", server.RemoteAddr())
				stream.Write([]byte("Hello!\n"))
				stream.CancelRead(0)
				stream.Close()
			}()
		}
	}()

	client, err := Dial(t.Context(), "udp", "example.com", &tls.Config{
		ServerName:                     "example.com",
		RootCAs:                        rootCAs,
		NextProtos:                     []string{"foo"},
		EncryptedClientHelloConfigList: nil, // Should come from DNS
	}, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Logf("Client connected to %s", client.RemoteAddr())
	if !client.ConnectionState().TLS.ECHAccepted {
		t.Errorf("Client ECHAccepted is false")
	}
	stream, err := client.OpenStreamSync(t.Context())
	if err != nil {
		t.Fatalf("client.OpenStream: %v", err)
	}
	defer stream.Close()
	stream.Write([]byte("Hi\n"))
	b, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if got, want := string(b), "Hello!\n"; got != want {
		t.Errorf("Got %q, want %q", got, want)
	}
}