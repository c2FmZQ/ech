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

// NewTransport returns a [Transport] that is ready to be used with
// [http.Client].
//
// By default, the returned [Transport] uses Encrypted Client Hello opportunistically
// and refuses to execute plaintext HTTP transactions. This behavior can be changed
// by modifiying the appropriate parameters.
//
// For example, to require ECH, set Dialer.RequireECH = true. To allow plaintext
// HTTP, set HTTPTransport.DialContext = nil.
func NewTransport() *Transport {
	t := &Transport{
		HTTPTransport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("attempting to dial a plaintext tcp connection")
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Resolver: DefaultResolver,
	}
	t.Dialer = NewDialer()
	t.Dialer.Resolver = transportResolver{}
	t.HTTPTransport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return t.Dialer.Dial(ctx, network, addr, t.TLSConfig)
	}
	return t
}

// Transport is a [http.RoundTripper] that uses [Resolver], [Dialer], and
// [http.Transport] to execute an HTTP transaction using Encrypted Client Hello
// in the underlying TLS connection.
type Transport struct {
	// This http.Transport is used to execute the HTTP transaction. The
	// DialContext and DialTLSContext functions are set by NewTransport
	// and should not be modified.
	HTTPTransport *http.Transport
	// This Resolver is used for DNS name resolution. NewTransport() sets
	// it to DefaultResolver. Any valid Resolver can be used.
	Resolver *Resolver
	// This Dialer is used to dial the TLS connection. Its parameters can
	// be modified as needed.
	Dialer *Dialer[*tls.Conn]
	// This tls.Config is used when dialing the TLS connection. A nil value
	// is generally fine.
	TLSConfig *tls.Config
}

// RoundTrip implements the [http.RoundTripper] interface.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	res, err := t.Resolver.Resolve(ctx, req.URL.String())
	if err != nil {
		return nil, err
	}
	if len(res.HTTPS) > 0 && req.URL.Scheme == "http" {
		req.URL.Scheme = "https"
	}
	req = req.WithContext(context.WithValue(ctx, resolveResult, res))
	return t.HTTPTransport.RoundTrip(req)
}

type ctxKey int

var resolveResult ctxKey = 1

type transportResolver struct{}

func (transportResolver) Resolve(ctx context.Context, name string) (ResolveResult, error) {
	res, ok := ctx.Value(resolveResult).(ResolveResult)
	if !ok {
		return res, errors.New("no result")
	}
	return res, nil
}
