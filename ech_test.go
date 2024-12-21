package ech

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
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
	}}))
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
			}}))
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
		}}))
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

func TestNoInner(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("public.example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	keys := []Key{{Config: config, PrivateKey: privKey.Bytes()}}

	outer := newClientHello("private", "tls1.3")
	c := newFakeConn(outer.bytes())

	conn, err := New(t.Context(), c, WithKeys(keys))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if buf, err := readRecord(conn); err != nil {
		t.Fatalf("ClientHello: %v", err)
	} else if got, want := buf, outer.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("ClientHello = %v, want %v", got, want)
	}
	if got, want := conn.ServerName(), "private.example.com"; got != want {
		t.Errorf("ServerName() = %q, want %q", got, want)
	}
	if got, want := conn.outer.tls13, true; got != want {
		t.Errorf("outer.tls13 = %v, want %v", got, want)
	}
	if got, want := conn.ECHAccepted(), false; got != want {
		t.Errorf("ECHAccepted = %v, want %v", got, want)
	}
}

func TestTLS12(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("public.example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	pubKey := privKey.PublicKey()
	keys := []Key{{Config: config, PrivateKey: privKey.Bytes()}}

	inner := newClientHello("private", "echExtInner", "tls1.3")
	outer := newClientHello("public", config, pubKey, inner)
	c := newFakeConn(outer.bytes())

	conn, err := New(t.Context(), c, WithKeys(keys))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if buf, err := readRecord(conn); err != nil {
		t.Fatalf("ClientHello: %v", err)
	} else if got, want := buf, outer.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("ClientHello = %v, want %v", got, want)
	}
	if got, want := conn.ServerName(), "public.example.com"; got != want {
		t.Errorf("ServerName() = %q, want %q", got, want)
	}
	if got, want := conn.outer.tls13, false; got != want {
		t.Errorf("outer.tls13 = %v, want %v", got, want)
	}
	if got, want := conn.ECHAccepted(), false; got != want {
		t.Errorf("ECHAccepted = %v, want %v", got, want)
	}
}

func TestValidInner(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("public.example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	pubKey := privKey.PublicKey()
	keys := []Key{{Config: config, PrivateKey: privKey.Bytes()}}

	inner := newClientHello("private", "echExtInner", "tls1.3")
	outer := newClientHello("public", "tls1.3", config, pubKey, inner)
	c := newFakeConn(outer.bytes())

	conn, err := New(t.Context(), c, WithKeys(keys))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if buf, err := readRecord(conn); err != nil {
		t.Fatalf("ClientHello: %v", err)
	} else if got, want := buf, inner.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("ClientHello = %v, want %v", got, want)
	}
	if got, want := conn.ServerName(), "private.example.com"; got != want {
		t.Errorf("ServerName() = %q, want %q", got, want)
	}
	if got, want := conn.ECHAccepted(), true; got != want {
		t.Errorf("ECHAccepted = %v, want %v", got, want)
	}
}

func TestOuterHasECHOuterExt(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("public.example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	keys := []Key{{Config: config, PrivateKey: privKey.Bytes()}}

	outer := newClientHello("public", "tls1.3", "ech_outer_extensions")
	c := newFakeConn(outer.bytes())

	if _, err := New(t.Context(), c, WithKeys(keys)); !errors.Is(err, ErrIllegalParameter) {
		t.Fatalf("New() = %v, want ErrIllegalParameter", err)
	}
}

func TestValidRetry(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("public.example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	pubKey := privKey.PublicKey()
	keys := []Key{{Config: config, PrivateKey: privKey.Bytes()}}

	inner1 := newClientHello("private", "echExtInner", "tls1.3")
	outer1 := newClientHello("public", "tls1.3", config, pubKey, inner1)
	inner2 := newClientHello("private", "echExtInner", "tls1.3")
	outer2 := newClientHello("public", "tls1.3", outer1.hpkeCtx, config, pubKey, inner2)
	c := newFakeConn(append(outer1.bytes(), outer2.bytes()...))

	conn, err := New(t.Context(), c, WithKeys(keys))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if buf, err := readRecord(conn); err != nil {
		t.Fatalf("First ClientHello: %v", err)
	} else if got, want := buf, inner1.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("First ClientHello = %v, want %v", got, want)
	}
	if got, want := conn.ServerName(), "private.example.com"; got != want {
		t.Errorf("ServerName() = %q, want %q", got, want)
	}
	if got, want := conn.ECHAccepted(), true; got != want {
		t.Errorf("ECHAccepted = %v, want %v", got, want)
	}
	if _, err := conn.Write(helloRetryReq()); err != nil {
		t.Fatalf("Write(helloRetryReq): %v", err)
	}
	if buf, err := readRecord(conn); err != nil {
		t.Fatalf("Second ClientHello: %v", err)
	} else if got, want := buf, inner2.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("Second ClientHello = %v, want %v", got, want)
	}
}

func TestRetryChangesServerName(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("public.example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	pubKey := privKey.PublicKey()
	keys := []Key{{Config: config, PrivateKey: privKey.Bytes()}}

	inner1 := newClientHello("private", "echExtInner", "tls1.3")
	outer1 := newClientHello("public", "tls1.3", config, pubKey, inner1)
	inner2 := newClientHello("public", "echExtInner", "tls1.3")
	outer2 := newClientHello("public", "tls1.3", outer1.hpkeCtx, config, pubKey, inner2)
	c := newFakeConn(append(outer1.bytes(), outer2.bytes()...))

	conn, err := New(t.Context(), c, WithKeys(keys))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if buf, err := readRecord(conn); err != nil {
		t.Fatalf("First ClientHello: %v", err)
	} else if got, want := buf, inner1.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("First ClientHello = %v, want %v", got, want)
	}
	if got, want := conn.ServerName(), "private.example.com"; got != want {
		t.Errorf("ServerName() = %q, want %q", got, want)
	}
	if got, want := conn.ECHAccepted(), true; got != want {
		t.Errorf("ECHAccepted = %v, want %v", got, want)
	}
	if _, err := conn.Write(helloRetryReq()); err != nil {
		t.Fatalf("Write(helloRetryReq): %v", err)
	}
	if _, err := readRecord(conn); !errors.Is(err, ErrIllegalParameter) {
		t.Fatalf("Second ClientHello: %v, want ErrIllegalParameter", err)
	}
}

func TestChangeHpkeKeyNotAllowed(t *testing.T) {
	privKey, config, err := NewConfig(1, []byte("public.example.com"))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	pubKey := privKey.PublicKey()
	keys := []Key{{Config: config, PrivateKey: privKey.Bytes()}}

	inner1 := newClientHello("private", "echExtInner", "tls1.3")
	outer1 := newClientHello("public", "tls1.3", config, pubKey, inner1)
	inner2 := newClientHello("private", "echExtInner", "tls1.3")
	outer2 := newClientHello("public", "tls1.3", config, pubKey, inner2)
	c := newFakeConn(append(outer1.bytes(), outer2.bytes()...))

	conn, err := New(t.Context(), c, WithKeys(keys))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if buf, err := readRecord(conn); err != nil {
		t.Fatalf("First ClientHello: %v", err)
	} else if got, want := buf, inner1.bytes(); !bytes.Equal(got, want) {
		t.Fatalf("First ClientHello = %v, want %v", got, want)
	}
	if got, want := conn.ServerName(), "private.example.com"; got != want {
		t.Errorf("ServerName() = %q, want %q", got, want)
	}
	if got, want := conn.ECHAccepted(), true; got != want {
		t.Errorf("ECHAccepted = %v, want %v", got, want)
	}
	if _, err := conn.Write(helloRetryReq()); err != nil {
		t.Fatalf("Write(helloRetryReq): %v", err)
	}
	if _, err := readRecord(conn); !errors.Is(err, ErrIllegalParameter) {
		t.Fatalf("Second ClientHello = %v, want ErrIllegalParameter", err)
	}
}
