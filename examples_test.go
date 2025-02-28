package ech

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func ExampleConfigList() {
	_, config, err := NewConfig(1, []byte("example.com"))
	if err != nil {
		log.Fatalf("NewConfig: %v", err)
	}
	configList, err := ConfigList([]Config{config})
	if err != nil {
		log.Fatalf("ConfigList: %v", err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(configList))
}

func ExampleDial() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := Dial(ctx, "tcp", "private.example.com", &tls.Config{})
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprintln(conn, "Hello!")
}

func ExampleDial_multiple() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := Dial(ctx, "tcp", "private1.example.com,private2.example.com", &tls.Config{})
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprintln(conn, "Hello!")
}

func ExampleDial_multiple_ip_addresses() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := Dial(ctx, "tcp", "192.168.0.1,192.168.0.2,192.168.0.3", &tls.Config{})
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprintln(conn, "Hello!")
}

func ExampleDial_with_ports() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := Dial(ctx, "tcp", "private1.example.com:8443,private2.example.com:10443,192.168.0.3", &tls.Config{})
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprintln(conn, "Hello!")
}

func ExampleDial_uri() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := Dial(ctx, "tcp", "https://private.example.com:8443", &tls.Config{})
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprintln(conn, "Hello!")
}

func ExampleNewConn() {
	ctx := context.Background()

	privKey, config, err := NewConfig(1, []byte("public.example.com"))
	if err != nil {
		log.Fatalf("NewConfig: %v", err)
	}

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	for {
		serverConn, err := ln.Accept()
		if err != nil {
			log.Fatalf("ln.Accept: %v", err)
		}
		conn, err := NewConn(ctx, serverConn, WithKeys([]Key{{
			Config:      config,
			PrivateKey:  privKey.Bytes(),
			SendAsRetry: true,
		}}))
		if err != nil {
			log.Printf("NewConn: %v", err)
			continue
		}

		switch host := conn.ServerName(); host {
		case "public.example.com":
			// Forward conn to a tls.Server for public.example.com
			// ...

		default:
			// Forward conn to a tls.Server for conn.ServerName()
			// ...
		}
	}
}

func ExampleNewDialer() {
	dialer := NewDialer()
	dialer.RequireECH = true
	dialer.PublicName = "public.example.com"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	conn, err := dialer.Dial(ctx, "tcp", "private.example.com", &tls.Config{})
	cancel()

	if err != nil {
		log.Fatalf("dialer.Dial: %v", err)
	}
	defer conn.Close()

	fmt.Fprintln(conn, "Hello!")
}

func ExampleResolver_Resolve() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := DefaultResolver.Resolve(ctx, "private.example.com")
	if err != nil {
		log.Fatalf("Resolve: %v", err)
	}

	for target := range result.Targets("tcp") {
		fmt.Printf("Address: %s  ECH: %s\n", target.Address, base64.StdEncoding.EncodeToString(target.ECH))
	}
}

func ExampleResolver_Resolve_with_port() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := DefaultResolver.Resolve(ctx, "private.example.com:8443")
	if err != nil {
		log.Fatalf("Resolve: %v", err)
	}

	for target := range result.Targets("tcp") {
		fmt.Printf("Address: %s  ECH: %s\n", target.Address, base64.StdEncoding.EncodeToString(target.ECH))
	}
}

func ExampleResolver_Resolve_with_uri() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := DefaultResolver.Resolve(ctx, "https://private.example.com:8443")
	if err != nil {
		log.Fatalf("Resolve: %v", err)
	}

	for target := range result.Targets("tcp") {
		fmt.Printf("Address: %s  ECH: %s\n", target.Address, base64.StdEncoding.EncodeToString(target.ECH))
	}
}

func ExampleTransport() {
	url := "https://private.example.com"

	transport := NewTransport()
	transport.Dialer.RequireECH = true

	client := &http.Client{Transport: transport}

	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("%q: %v", url, err)
	}
	defer resp.Body.Close()
	fmt.Printf("==== %s Status:%d ====\n", url, resp.StatusCode)
	io.Copy(os.Stdout, resp.Body)
}
