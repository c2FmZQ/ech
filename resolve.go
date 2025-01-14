package ech

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"

	"github.com/c2FmZQ/ech/dns"
)

// ResolveResult contains the A and HTTPS records.
type ResolveResult struct {
	A     []net.IP
	AAAA  []net.IP
	HTTPS []dns.HTTPS
}

// Addr is a convenience function that returns a random IP address or an empty
// string.
func (r ResolveResult) Addr() string {
	if n := len(r.A); n > 0 {
		return r.A[random(n)].String()
	}
	if n := len(r.AAAA); n > 0 {
		return r.AAAA[random(n)].String()
	}
	for _, h := range r.HTTPS {
		if len(h.IPv4Hint) > 0 {
			return h.IPv4Hint.String()
		}
		if len(h.IPv6Hint) > 0 {
			return h.IPv6Hint.String()
		}
	}
	return ""
}

// ECH is a convenience function that returns the first ECH value or nil.
func (r ResolveResult) ECH() []byte {
	for _, h := range r.HTTPS {
		if len(h.ECH) > 0 {
			return h.ECH
		}
	}
	return nil
}

// Resolve uses the default DNS-over-HTTPS resolver (currently cloudflare) to
// resolve name.
func Resolve(ctx context.Context, name string) (ResolveResult, error) {
	return defaultResolver.Resolve(ctx, name)
}

var defaultResolver = CloudflareResolver()

// CloudflareResolver uses Cloudflare's DNS-over-HTTPS service.
// https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
func CloudflareResolver() *Resolver {
	return &Resolver{
		baseURL: url.URL{Scheme: "https", Host: "1.1.1.1", Path: "/dns-query"},
	}
}

// GoogleResolver uses Google's DNS-over-HTTPS service.
// https://developers.google.com/speed/public-dns/docs/doh
func GoogleResolver() *Resolver {
	return &Resolver{
		baseURL: url.URL{Scheme: "https", Host: "dns.google", Path: "/dns-query"},
	}
}

// WikimediaResolver uses Wikimedia's DNS-over-HTTPS service.
// https://meta.wikimedia.org/wiki/Wikimedia_DNS
func WikimediaResolver() *Resolver {
	return &Resolver{
		baseURL: url.URL{Scheme: "https", Host: "wikimedia-dns.org", Path: "/dns-query"},
	}
}

// NewResolver returns a resolver that uses any RFC 8484 compliant
// DNS-over-HTTPS service.
// See https://github.com/curl/curl/wiki/DNS-over-HTTPS#publicly-available-servers
// for a list of publicly available servers.
func NewResolver(URL string) (*Resolver, error) {
	u, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" {
		return nil, errors.New("service url must use https")
	}
	return &Resolver{
		baseURL: *u,
	}, nil
}

// Resolver is a DNS-over-HTTPS client.
type Resolver struct {
	baseURL url.URL
}

// Resolve uses DNS-over-HTTPS to resolve name.
func (r *Resolver) Resolve(ctx context.Context, name string) (ResolveResult, error) {
	result := ResolveResult{}
	if name == "localhost" {
		result.A = []net.IP{net.IP{127, 0, 0, 1}}
		result.AAAA = []net.IP{net.IPv6loopback}
		return result, nil
	}
	if ip := net.ParseIP(name); ip != nil {
		if len(ip) == 4 {
			result.A = []net.IP{ip.To4()}
		} else {
			result.AAAA = []net.IP{ip}
		}
		return result, nil
	}
	a, err := r.resolveOne(ctx, name, "A")
	if err != nil {
		return result, err
	}
	for _, v := range a {
		result.A = append(result.A, v.(net.IP))
	}
	aaaa, err := r.resolveOne(ctx, name, "AAAA")
	if err != nil {
		return result, err
	}
	for _, v := range aaaa {
		result.AAAA = append(result.AAAA, v.(net.IP))
	}
	https, err := r.resolveOne(ctx, name, "HTTPS")
	if err != nil {
		return result, err
	}
	for _, v := range https {
		result.HTTPS = append(result.HTTPS, v.(dns.HTTPS))
	}
	return result, nil
}

var (
	ErrFormatError       = errors.New("format error")
	ErrServerFailure     = errors.New("server failure")
	ErrNonExistentDomain = errors.New("non-existent domain")
	ErrNotImplemented    = errors.New("not implemented")
	ErrQueryRefused      = errors.New("query refused")

	rcode = map[uint8]error{
		1: ErrFormatError,
		2: ErrServerFailure,
		3: ErrNonExistentDomain,
		4: ErrNotImplemented,
		5: ErrQueryRefused,
	}
)

func (r *Resolver) resolveOne(ctx context.Context, name, typ string) ([]any, error) {
	qq := &dns.Message{
		ID: 0x0000,
		RD: 1,
		Question: []dns.Question{{
			Name:  name,
			Type:  dns.RRType(typ),
			Class: 1,
		}},
	}

	result, err := dns.DoH(ctx, qq, r.baseURL.String())
	if err != nil {
		return nil, err
	}

	if rc := result.RCode; rc != 0 {
		if err := rcode[rc]; err != nil {
			return nil, fmt.Errorf("%s (%s): %w (%d)", name, typ, rcode[rc], rc)
		}
		return nil, fmt.Errorf("%s (%s): response code %d", name, typ, rc)
	}
	var res []any
	want := strings.TrimSuffix(name, ".")
	for _, a := range result.Answer {
		name := strings.TrimSuffix(a.Name, ".")
		if name == want && a.Type == dns.RRType(typ) {
			res = append(res, a.Data)
		}
		if name == want && a.Type == 5 { // CNAME
			want = strings.TrimSuffix(a.Data.(string), ".")
			continue
		}
	}
	return res, nil
}

func random(n int) int {
	if n < 2 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}
