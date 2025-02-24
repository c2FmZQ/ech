package ech

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
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

func ExampleResolve() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := Resolve(ctx, "private.example.com")
	if err != nil {
		log.Fatalf("Resolve: %v", err)
	}

	for target := range result.Targets("tcp", 443) {
		fmt.Printf("Address: %s  ECH: %s\n", target.Address, base64.StdEncoding.EncodeToString(target.ECH))
	}
}
