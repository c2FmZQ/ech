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
// until a connection is successfully established. See [ech.Dialer] for finer
// control.
func Dial(ctx context.Context, network, addr string, tc *tls.Config, qc *quic.Config) (quic.Connection, error) {
	return NewDialer(qc).Dial(ctx, network, addr, tc)
}

// NewDialer returns a [quic.Connection] Dialer.
func NewDialer(qc *quic.Config) *ech.Dialer[quic.Connection] {
	return &ech.Dialer[quic.Connection]{
		DialFunc: func(ctx context.Context, network, addr string, tc *tls.Config) (quic.Connection, error) {
			return quic.DialAddr(ctx, addr, tc, qc)
		},
	}
}
