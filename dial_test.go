package ech

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
		{"h1.example.com", 0, nil},            // port & config list from DNS
		{"h2.example.com", 0, nil},            // port & config list from DNS (retry)
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

func TestDialer(t *testing.T) {
	_, config, err := NewConfig(1, []byte("example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	configList, err := ConfigList([]Config{config})
	if err != nil {
		t.Fatalf("ConfigList: %v", err)
	}
	dnsServer := testutil.StartTestDNSServer(t, []dns.RR{{
		Name: "h1.example.com", Type: 65, Class: 1, TTL: 60,
		Data: dns.HTTPS{
			Priority: 1,
			Port:     1000,
			IPv4Hint: []net.IP{
				{1, 0, 0, 1},
				{1, 0, 0, 2},
				{1, 0, 0, 3},
				{1, 0, 0, 4},
				{1, 0, 0, 5},
			},
			ECH: configList,
		},
	}, {
		Name: "h1.example.com", Type: 65, Class: 1, TTL: 60,
		Data: dns.HTTPS{
			Priority: 2,
			Port:     2000,
			IPv4Hint: []net.IP{
				{2, 0, 0, 1},
				{2, 0, 0, 2},
				{2, 0, 0, 3},
				{2, 0, 0, 4},
				{2, 0, 0, 5},
			},
		},
	}, {
		Name: "h1.example.com", Type: 1, Class: 1, TTL: 60,
		Data: net.IP{3, 0, 0, 1},
	}, {
		Name: "h2.example.com", Type: 1, Class: 1, TTL: 60,
		Data: net.IP{4, 0, 0, 1},
	}})
	defer dnsServer.Close()

	dialer := &Dialer[string]{
		Resolver: &Resolver{
			baseURL: url.URL{
				Scheme: "http",
				Host:   dnsServer.Listener.Addr().String(),
				Path:   "/dns-query",
			},
		},
		PublicName:       "example.com",
		MaxConcurrency:   4,
		ConcurrencyDelay: 50 * time.Millisecond,
		Timeout:          20 * time.Millisecond,
		DialFunc: func(ctx context.Context, network, addr string, tc *tls.Config) (string, error) {
			t.Logf("Dial %q", addr)
			var ech string
			if tc.EncryptedClientHelloConfigList == nil {
				ech = " ECH nil"
			} else if bytes.Equal(tc.EncryptedClientHelloConfigList, configList) {
				ech = " ECH OK"
			} else {
				list, err := ParseConfigList(tc.EncryptedClientHelloConfigList)
				if err != nil {
					return "", err
				}
				if len(list) != 1 {
					return "", fmt.Errorf("bad config list: %#v", list)
				}
				ech = " ECH publicname:" + string(list[0].PublicName)
			}
			<-ctx.Done()
			return "", fmt.Errorf("pseudo-error %q%s", addr, ech)
		},
	}

	t.Run("MultipleTargetsWithPublicName", func(t *testing.T) {
		_, got := dialer.Dial(t.Context(), "tcp", "h1.example.com", nil)
		want := strings.TrimSpace(strings.ReplaceAll(`
			h1.example.com: pseudo-error "3.0.0.1:1000" ECH OK
			h1.example.com: pseudo-error "3.0.0.1:2000" ECH publicname:example.com`, "\t", ""))
		if got.Error() != want {
			t.Errorf("Got %q, want %q", got, want)
		}
	})

	t.Run("OneTargetNoECHWithPublicName", func(t *testing.T) {
		_, got := dialer.Dial(t.Context(), "tcp", "h2.example.com", nil)
		want := strings.TrimSpace(strings.ReplaceAll(`
			h2.example.com: pseudo-error "4.0.0.1:443" ECH publicname:example.com`, "\t", ""))
		if got.Error() != want {
			t.Errorf("Got %q, want %q", got, want)
		}
	})

	t.Run("MultipleTargetsMultipleAddressesWithPublicName", func(t *testing.T) {
		_, got := dialer.Dial(t.Context(), "tcp", "h1.example.com,h2.example.com:8443", nil)
		want := strings.TrimSpace(strings.ReplaceAll(`
			h1.example.com: pseudo-error "3.0.0.1:1000" ECH OK
			h1.example.com: pseudo-error "3.0.0.1:2000" ECH publicname:example.com
			h2.example.com: pseudo-error "4.0.0.1:8443" ECH publicname:example.com`, "\t", ""))
		if got.Error() != want {
			t.Errorf("Got %q, want %q", got, want)
		}
	})

	dialer.PublicName = ""
	t.Run("MultipleTargetsNoPublicName", func(t *testing.T) {
		_, got := dialer.Dial(t.Context(), "tcp", "h1.example.com", nil)
		want := strings.TrimSpace(strings.ReplaceAll(`
			h1.example.com: pseudo-error "3.0.0.1:1000" ECH OK
			h1.example.com: pseudo-error "3.0.0.1:2000" ECH nil`, "\t", ""))
		if got.Error() != want {
			t.Errorf("Got %q, want %q", got, want)
		}
	})

	dialer.RequireECH = true
	t.Run("MultipleTargetsNoPublicNameRequireECH", func(t *testing.T) {
		_, got := dialer.Dial(t.Context(), "tcp", "h1.example.com", nil)
		want := strings.TrimSpace(strings.ReplaceAll(`
			h1.example.com: pseudo-error "3.0.0.1:1000" ECH OK
			h1.example.com: unable to get ECH config list`, "\t", ""))
		if got.Error() != want {
			t.Errorf("Got %q, want %q", got, want)
		}
	})

	t.Run("OneTargetNoECHNoPublicNameRequireECH", func(t *testing.T) {
		_, got := dialer.Dial(t.Context(), "tcp", "h2.example.com", nil)
		want := "h2.example.com: unable to get ECH config list"
		if got.Error() != want {
			t.Errorf("Got %q, want %q", got, want)
		}
	})
}

type fakeCloserConn struct {
	addr   string
	closed *atomic.Int32
}

func (c *fakeCloserConn) Close() error {
	c.closed.Add(1)
	return nil
}

type fakeAppErrorCode uint64

type fakeQUICConn struct {
	addr   string
	closed *atomic.Int32
}

func (c *fakeQUICConn) CloseWithError(_ fakeAppErrorCode, _ string) error {
	c.closed.Add(1)
	return nil
}

func TestDialerStopsAndClosesLosingConns(t *testing.T) {
	var resolvedH2 atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		body, _ := io.ReadAll(req.Body)
		qq, err := dns.DecodeMessage(body)
		if err != nil {
			t.Errorf("dns.DecodeMessage: %v", err)
			return
		}
		qq.QR = 1
		q := qq.Question[0]
		switch q.Name {
		case "h1.example.com":
			if q.Type == 1 {
				qq.Answer = []dns.RR{
					{Name: "h1.example.com", Type: 1, Class: 1, TTL: 60, Data: net.IP{1, 0, 0, 1}},
					{Name: "h1.example.com", Type: 1, Class: 1, TTL: 60, Data: net.IP{1, 0, 0, 2}},
					{Name: "h1.example.com", Type: 1, Class: 1, TTL: 60, Data: net.IP{1, 0, 0, 3}},
				}
			}
		case "h2.example.com":
			resolvedH2.Add(1)
			if q.Type == 1 {
				qq.Answer = []dns.RR{
					{Name: "h2.example.com", Type: 1, Class: 1, TTL: 60, Data: net.IP{2, 0, 0, 1}},
				}
			}
		}
		w.Write(qq.Bytes())
	}))
	defer ts.Close()

	t.Run("IOCloser", func(t *testing.T) {
		resolvedH2.Store(0)
		var dialed atomic.Int32
		var closedConns atomic.Int32
		loseDone := make(chan struct{})

		dialer := &Dialer[*fakeCloserConn]{
			Resolver: &Resolver{
				baseURL: url.URL{Scheme: "http", Host: ts.Listener.Addr().String(), Path: "/dns-query"},
			},
			MaxConcurrency:   3,
			ConcurrencyDelay: 20 * time.Millisecond,
			Timeout:          time.Second,
			DialFunc: func(ctx context.Context, network, addr string, tc *tls.Config) (*fakeCloserConn, error) {
				dialed.Add(1)
				switch addr {
				case "1.0.0.1:443":
					time.Sleep(35 * time.Millisecond)
					return &fakeCloserConn{addr: addr, closed: &closedConns}, nil
				case "1.0.0.2:443":
					time.Sleep(55 * time.Millisecond)
					defer close(loseDone)
					return &fakeCloserConn{addr: addr, closed: &closedConns}, nil
				default:
					return &fakeCloserConn{addr: addr, closed: &closedConns}, nil
				}
			},
		}

		conn, err := dialer.Dial(t.Context(), "tcp", "h1.example.com,h2.example.com", nil)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if conn.addr != "1.0.0.1:443" {
			t.Errorf("conn.addr = %q, want 1.0.0.1:443", conn.addr)
		}

		<-loseDone
		deadline := time.Now().Add(time.Second)
		for closedConns.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if got := closedConns.Load(); got != 1 {
			t.Errorf("closedConns = %d, want 1", got)
		}
		if got := resolvedH2.Load(); got != 0 {
			t.Errorf("resolvedH2 = %d, want 0", got)
		}
		if got := dialed.Load(); got != 2 {
			t.Errorf("dialed = %d, want 2", got)
		}
	})

	t.Run("CloseWithError", func(t *testing.T) {
		resolvedH2.Store(0)
		var dialed atomic.Int32
		var closedConns atomic.Int32
		loseDone := make(chan struct{})

		dialer := &Dialer[*fakeQUICConn]{
			Resolver: &Resolver{
				baseURL: url.URL{Scheme: "http", Host: ts.Listener.Addr().String(), Path: "/dns-query"},
			},
			MaxConcurrency:   3,
			ConcurrencyDelay: 20 * time.Millisecond,
			Timeout:          time.Second,
			DialFunc: func(ctx context.Context, network, addr string, tc *tls.Config) (*fakeQUICConn, error) {
				dialed.Add(1)
				switch addr {
				case "1.0.0.1:443":
					time.Sleep(35 * time.Millisecond)
					return &fakeQUICConn{addr: addr, closed: &closedConns}, nil
				case "1.0.0.2:443":
					time.Sleep(55 * time.Millisecond)
					defer close(loseDone)
					return &fakeQUICConn{addr: addr, closed: &closedConns}, nil
				default:
					return &fakeQUICConn{addr: addr, closed: &closedConns}, nil
				}
			},
		}

		conn, err := dialer.Dial(t.Context(), "udp", "h1.example.com,h2.example.com", nil)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if conn.addr != "1.0.0.1:443" {
			t.Errorf("conn.addr = %q, want 1.0.0.1:443", conn.addr)
		}

		<-loseDone
		deadline := time.Now().Add(time.Second)
		for closedConns.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if got := closedConns.Load(); got != 1 {
			t.Errorf("closedConns = %d, want 1", got)
		}
		if got := resolvedH2.Load(); got != 0 {
			t.Errorf("resolvedH2 = %d, want 0", got)
		}
		if got := dialed.Load(); got != 2 {
			t.Errorf("dialed = %d, want 2", got)
		}
	})
}
