// Package quic implements a [ech.Dialer] for QUIC connections.
//
// It uses [ech.Dialer] for name resolution and finding the Encrypted Client
// Hello (ECH) Config List, and [quic.DialAddr] for establishing the QUIC
// connection.
package quic

import (
	"context"
	"crypto/tls"

	"github.com/c2FmZQ/ech"
	"github.com/quic-go/quic-go"
)

// Dial connects to the given network and address. Name resolution is done with
// [ech.DefaultResolver]. It uses HTTPS DNS records to retrieve the server's
// Encrypted Client Hello (ECH) Config List and uses it automatically if found.
//
// If the name resolution returns multiple IP addresses, Dial iterates over them
// until a connection is successfully established.
//
// Dial is equivalent to:
//
//	NewDialer(...).Dial(...)
//
// For finer control, instantiate a [ech.Dialer] first with [NewDialer].  Then,
// call Dial, e.g.:
//
//	dialer := NewDialer(&quic.Config{})
//	dialer.RequireECH = true
//	conn, err := dialer.Dial(...)
func Dial(ctx context.Context, network, addr string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
	return NewDialer(qc).Dial(ctx, network, addr, tc)
}

// NewDialer returns a [quic.Connection] Dialer.
func NewDialer(qc *quic.Config) *ech.Dialer[*quic.Conn] {
	return &ech.Dialer[*quic.Conn]{
		DialFunc: func(ctx context.Context, network, addr string, tc *tls.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, addr, tc, qc)
		},
	}
}
