package ech

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

var _ http.RoundTripper = (*Transport)(nil)

func NewTransport() *Transport {
	t := &Transport{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("attempting to dial a plaintext tcp connection")
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Resolver: DefaultResolver,
	}
	t.Dialer = NewDialer()
	t.Dialer.Resolver = transportResolver{}
	t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return t.Dialer.Dial(ctx, network, addr, t.TLSConfig)
	}
	return t
}

// Transport is a [http.RoundTripper] that uses [Resolver], [Dialer], and
// [http.Transport] to execute an HTTP transaction.
type Transport struct {
	*http.Transport
	Resolver  *Resolver
	Dialer    *Dialer[*tls.Conn]
	TLSConfig *tls.Config
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	res, err := t.Resolver.Resolve(ctx, req.URL.String())
	if err != nil {
		return nil, err
	}
	if len(res.HTTPS) > 0 && req.URL.Scheme == "http" {
		req.URL.Scheme = "https"
	}
	ctx = context.WithValue(ctx, resolveResult, res)
	req = req.WithContext(ctx)
	return t.Transport.RoundTrip(req)
}

type ctxKey int

var resolveResult ctxKey = 1

type transportResolver struct{}

func (transportResolver) Resolve(ctx context.Context, name string) (ResolveResult, error) {
	return ctx.Value(resolveResult).(ResolveResult), nil
}
