package h3

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/c2FmZQ/ech"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// NewTransport returns a [ech.Transport] that is ready to be used with
// [http.Client]. This Transport uses the HTTP/3 protocol with the hostname
// has a HTTPS RR with h3 in its ALPN list.
func NewTransport(qc *quic.Config) *ech.Transport {
	dialer := &ech.Dialer[quic.EarlyConnection]{
		DialFunc: func(ctx context.Context, network, addr string, tc *tls.Config) (quic.EarlyConnection, error) {
			return quic.DialAddrEarly(ctx, addr, tc, qc)
		},
	}
	var once sync.Once

	t := ech.NewTransport()
	t.HTTP3Transport = &http3.Transport{
		Dial: func(ctx context.Context, addr string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
			once.Do(func() {
				dialer.RequireECH = t.Dialer.RequireECH
				dialer.PublicName = t.Dialer.PublicName
				dialer.MaxConcurrency = t.Dialer.MaxConcurrency
				dialer.ConcurrencyDelay = t.Dialer.ConcurrencyDelay
			})
			return dialer.Dial(ctx, "udp", addr, t.TLSConfig)
		},
	}
	return t
}
