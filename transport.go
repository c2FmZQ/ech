package ech

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/c2FmZQ/ech/dns"
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
		Resolver: DefaultResolver,
		Dialer:   NewDialer(),
	}
	t.HTTPTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("attempting to dial a plaintext tcp connection")
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return t.Dialer.Dial(ctx, network, addr, t.TLSConfig)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
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
	// This RoundTripper is used to execute the HTTP transaction using the
	// HTTP/3 protocol. This value is optional. If set, it is used only when
	// the hostname has an HTTPS RR with h3 present in its ALPN list with a
	// lower Priority value than any with h2 or http/1.1.
	// See github.com/c2FmZQ/ech/quic/h3 NewTransport
	HTTP3Transport http.RoundTripper
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
	origReq := req
	req = req.Clone(ctx)

	if len(res.HTTPS) > 0 && req.URL.Scheme == "http" {
		req.URL.Scheme = "https"
	}

	h, p, err := net.SplitHostPort(req.URL.Host)
	if err != nil {
		h = req.URL.Host
		switch req.URL.Scheme {
		case "http":
			p = "80"
		default:
			p = "443"
		}
	}
	if req.Host == "" {
		// This is the value sent in the Host / :authority header.
		req.Host = req.URL.Host
	}

	// The URL.Host is typically used by the http transport to decide which
	// connections are equivalent and can be used or re-used interchangeably.
	// The value is used as a key only. The format doesn't matter.
	req.URL.Host = fmt.Sprintf("_%s._%s.%s._", p, req.URL.Scheme, h)

	var useH3 bool
	if t.HTTP3Transport != nil {
		for _, hh := range res.HTTPS {
			if hh.Priority == 0 {
				continue
			}
			if slices.Contains(hh.ALPN, "h3") {
				useH3 = true
				break
			}
			if !hh.NoDefaultALPN || slices.Contains(hh.ALPN, "h2") || slices.Contains(hh.ALPN, "http/1.1") {
				break
			}
		}
	}

	filterResult := func(alpn map[string]bool, mustHave bool) ResolveResult {
		result := res.clone()
		result.HTTPS = slices.DeleteFunc(result.HTTPS, func(hh dns.HTTPS) bool {
			if hh.Priority == 0 {
				return true
			}
			if !mustHave && len(hh.ALPN) == 0 {
				return false
			}
			if !hh.NoDefaultALPN && alpn["http/1.1"] {
				return false
			}
			for _, p := range hh.ALPN {
				if alpn[p] {
					return false
				}
			}
			return true
		})
		return result
	}

	var resp *http.Response
	if useH3 {
		resp, err = t.HTTP3Transport.RoundTrip(
			req.WithContext(
				context.WithValue(ctx, transportResolverKey, &transportResolver{
					host:   h,
					result: filterResult(map[string]bool{"h3": true}, true),
				}),
			),
		)
	} else {
		resp, err = t.HTTPTransport.RoundTrip(
			req.WithContext(
				context.WithValue(ctx, transportResolverKey, &transportResolver{
					host:   h,
					result: filterResult(map[string]bool{"h2": true, "http/1.1": true}, false),
				}),
			),
		)
	}
	if err != nil {
		return nil, err
	}
	resp.Request = origReq
	return resp, nil
}

type ctxTransportKey int

var transportResolverKey ctxTransportKey = 1

type transportResolver struct {
	host   string
	result ResolveResult
}

func (r *transportResolver) Resolve(ctx context.Context, name string) (ResolveResult, error) {
	return r.result, nil
}
