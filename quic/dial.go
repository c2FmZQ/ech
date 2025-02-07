package quic

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/c2FmZQ/ech"
	"github.com/quic-go/quic-go"
)

// Dial connects to the given network and address using [quic.DialAddr]. Name
// resolution is done with [ech.DefaultResolver] and EncryptedClientHelloConfigList
// will be set automatically if the hostname has a HTTPS DNS record with ech.
func Dial(ctx context.Context, network, addr string, tc *tls.Config, qc *quic.Config) (quic.Connection, error) {
	return NewDialer(qc).Dial(ctx, network, addr, tc)
}

// NewDialer returns a [quic.Connection] Dialer.
func NewDialer(qc *quic.Config) *ech.Dialer[quic.Connection] {
	return &ech.Dialer[quic.Connection]{
		DialFunc: func(ctx context.Context, network, addr string, tc *tls.Config) (quic.Connection, error) {
			var retried bool
		retry:
			conn, err := quic.DialAddr(ctx, addr, tc, qc)
			if err != nil {
				var echErr *tls.ECHRejectionError
				if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 && !retried {
					tc.EncryptedClientHelloConfigList = echErr.RetryConfigList
					retried = true
					goto retry
				}
				return nil, err
			}
			return conn, nil
		},
	}
}
