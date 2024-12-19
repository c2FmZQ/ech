package ech

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestConn(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("example.com"))
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
	tlsCert, err := newCert("www.example.com", "example.com")
	if err != nil {
		t.Fatalf("newCert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(tlsCert.Leaf)

	ch := make(chan string)
	go func() {
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Errorf("net.Dial: %v", err)
			return
		}
		client := tls.Client(clientConn, &tls.Config{
			ServerName:                     "www.example.com",
			RootCAs:                        rootCAs,
			NextProtos:                     []string{"h2", "http/1.1"},
			EncryptedClientHelloConfigList: configList,
		})
		if _, err := client.Write([]byte("hello\n")); err != nil {
			t.Errorf("client.Write: %v", err)
		}
		b := make([]byte, 1024)
		n, err := client.Read(b)
		if err != nil {
			t.Errorf("client.Read: %v", err)
		}
		t.Logf("client ECHAccepted: %v", client.ConnectionState().ECHAccepted)
		ch <- string(b[:n])
	}()

	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("ln.Accept: %v", err)
	}
	outConn, err := New(t.Context(), serverConn, WithKeys([]Key{{
		Config:      config,
		PrivateKey:  privKey.Bytes(),
		SendAsRetry: true,
	}}), WithDebug(t.Logf))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Logf("Outer: %s", outConn.outer)
	t.Logf("Inner: %s", outConn.inner)
	t.Logf("Outer ServerName: %s", outConn.outer.ServerName)
	t.Logf("Outer ALPNProtos: %s", outConn.outer.ALPNProtos)
	t.Logf("Inner ServerName: %s", outConn.inner.ServerName)
	t.Logf("Inner ALPNProtos: %s", outConn.inner.ALPNProtos)

	server := tls.Server(outConn, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	b := make([]byte, 1024)
	n, err := server.Read(b)
	if err != nil {
		t.Fatalf("server.Read: %v", err)
	}
	if got, want := string(b[:n]), "hello\n"; got != want {
		t.Fatalf("Server read %q, want %q", got, want)
	}
	if _, err := server.Write([]byte("hi!\n")); err != nil {
		t.Fatalf("server.Write: %v", err)
	}
	t.Logf("server ECHAccepted: %v", server.ConnectionState().ECHAccepted)
	if got, want := <-ch, "hi!\n"; got != want {
		t.Fatalf("Client read %q, want %q", got, want)
	}
}

func TestConnRetry(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	_, config2, err := NewConfig(1, []byte("example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	configList, err := ConfigList([]Config{config2})
	if err != nil {
		t.Fatalf("ConfigList: %v", err)
	}

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	tlsCert, err := newCert("www.example.com", "example.com")
	if err != nil {
		t.Fatalf("newCert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(tlsCert.Leaf)

	t.Run("Wrong configlist", func(t *testing.T) {
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
		serverConn, err := ln.Accept()
		if err != nil {
			t.Fatalf("ln.Accept: %v", err)
		}
		go func() {
			outConn, err := New(t.Context(), serverConn, WithKeys([]Key{{
				Config:      config,
				PrivateKey:  privKey.Bytes(),
				SendAsRetry: true,
			}}), WithDebug(t.Logf))
			if err != nil {
				t.Errorf("New: %v", err)
				return
			}
			t.Logf("Outer: %s", outConn.outer)
			t.Logf("Inner: %s", outConn.inner)
			t.Logf("Outer ServerName: %s", outConn.outer.ServerName)
			t.Logf("Outer ALPNProtos: %s", outConn.outer.ALPNProtos)
			server := tls.Server(outConn, &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				MinVersion:   tls.VersionTLS13,
				EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
					Config:      config,
					PrivateKey:  privKey.Bytes(),
					SendAsRetry: true,
				}},
			})
			b := make([]byte, 1024)
			if _, err := server.Read(b); err == nil {
				t.Errorf("server.Read did not fail")
			}
		}()

		client := tls.Client(clientConn, &tls.Config{
			ServerName:                     "www.example.com",
			RootCAs:                        rootCAs,
			NextProtos:                     []string{"h2", "http/1.1"},
			EncryptedClientHelloConfigList: configList,
		})
		defer client.Close()
		_, err = client.Write([]byte("hello\n"))
		var echErr *tls.ECHRejectionError
		if !errors.As(err, &echErr) {
			t.Errorf("client.Write did not return a ECHRejectionError: %#v", err)
			return
		}
		configList = echErr.RetryConfigList
		t.Logf("retry ConfigList: %v", configList)
	})

	t.Run("Use retry configlist", func(t *testing.T) {
		clientConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial: %v", err)
		}
		serverConn, err := ln.Accept()
		if err != nil {
			t.Fatalf("ln.Accept: %v", err)
		}

		ch := make(chan string)
		go func() {
			client := tls.Client(clientConn, &tls.Config{
				ServerName:                     "www.example.com",
				RootCAs:                        rootCAs,
				NextProtos:                     []string{"h2", "http/1.1"},
				EncryptedClientHelloConfigList: configList,
			})
			if _, err := client.Write([]byte("hello\n")); err != nil {
				t.Errorf("client.Write: %v", err)
			}
			b := make([]byte, 1024)
			n, err := client.Read(b)
			if err != nil {
				t.Errorf("client.Read: %v", err)
			}
			t.Logf("client ECHAccepted: %v", client.ConnectionState().ECHAccepted)
			ch <- string(b[:n])
		}()

		outConn, err := New(t.Context(), serverConn, WithKeys([]Key{{
			Config:      config,
			PrivateKey:  privKey.Bytes(),
			SendAsRetry: true,
		}}), WithDebug(t.Logf))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Logf("Outer: %s", outConn.outer)
		t.Logf("Inner: %s", outConn.inner)
		t.Logf("Outer ServerName: %s", outConn.outer.ServerName)
		t.Logf("Outer ALPNProtos: %s", outConn.outer.ALPNProtos)
		t.Logf("Inner ServerName: %s", outConn.inner.ServerName)
		t.Logf("Inner ALPNProtos: %s", outConn.inner.ALPNProtos)

		server := tls.Server(outConn, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		})
		b := make([]byte, 1024)
		n, err := server.Read(b)
		if err != nil {
			t.Fatalf("server.Read: %v", err)
		}
		if got, want := string(b[:n]), "hello\n"; got != want {
			t.Fatalf("Server read %q, want %q", got, want)
		}
		if _, err := server.Write([]byte("hi!\n")); err != nil {
			t.Fatalf("server.Write: %v", err)
		}
		t.Logf("server ECHAccepted: %v", server.ConnectionState().ECHAccepted)
		if got, want := <-ch, "hi!\n"; got != want {
			t.Fatalf("Client read %q, want %q", got, want)
		}
	})
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
