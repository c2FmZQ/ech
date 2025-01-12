package ech

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ResolveResult contains the A and HTTPS records.
type ResolveResult struct {
	A     []string
	AAAA  []string
	HTTPS []HTTPS
}

// HTTPS represents a DNS HTTPS Resource Record.
// https://www.rfc-editor.org/rfc/rfc9460
type HTTPS struct {
	Priority      uint16
	Target        string
	ALPN          []string
	NoDefaultALPN bool
	Port          uint16
	IPv4Hint      net.IP
	IPv6Hint      net.IP
	ECH           []byte
}

func (h HTTPS) String() string {
	s := fmt.Sprintf("%d %s.", h.Priority, h.Target)
	if len(h.ALPN) > 0 {
		s += fmt.Sprintf(" alpn=%q", strings.Join(h.ALPN, ","))
	}
	if h.NoDefaultALPN {
		s += " no-default-alpn"
	}
	if h.Port > 0 {
		s += fmt.Sprintf(" port=%d", h.Port)
	}
	if len(h.IPv4Hint) > 0 {
		s += fmt.Sprintf(" ipv4-hint=%s", h.IPv4Hint)
	}
	if len(h.IPv6Hint) > 0 {
		s += fmt.Sprintf(" ipv6-hint=%s", h.IPv6Hint)
	}
	if len(h.ECH) > 0 {
		s += fmt.Sprintf(" ech=%q", base64.StdEncoding.EncodeToString(h.ECH))
	}
	return s
}

// Addr is a convenience function that returns a random IP address or an empty
// string.
func (r ResolveResult) Addr() string {
	if n := len(r.A); n > 0 {
		return r.A[random(n)]
	}
	if n := len(r.AAAA); n > 0 {
		return r.AAAA[random(n)]
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
		result.A = []string{"127.0.0.1"}
		result.AAAA = []string{net.IPv6loopback.String()}
		return result, nil
	}
	if ip := net.ParseIP(name); ip != nil {
		if len(ip) == 4 {
			result.A = []string{ip.String()}
		} else {
			result.AAAA = []string{ip.String()}
		}
		return result, nil
	}
	a, err := r.resolveOne(ctx, name, "A")
	if err != nil {
		return result, err
	}
	for _, v := range a {
		result.A = append(result.A, v.(string))
	}
	aaaa, err := r.resolveOne(ctx, name, "AAAA")
	if err != nil {
		return result, err
	}
	for _, v := range aaaa {
		result.AAAA = append(result.AAAA, v.(string))
	}
	https, err := r.resolveOne(ctx, name, "HTTPS")
	if err != nil {
		return result, err
	}
	for _, v := range https {
		result.HTTPS = append(result.HTTPS, v.(HTTPS))
	}
	return result, nil
}

var (
	rrTypes = map[string]uint16{
		"A":     1,
		"CNAME": 5,
		"AAAA":  28,
		"HTTPS": 65,
	}
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
	qq := &dnsMessage{
		id: 0x0000,
		rd: 1,
		question: []dnsQuestion{
			{
				name:  name,
				typ:   rrTypes[typ],
				class: 1,
			},
		},
	}
	u := r.baseURL
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(qq.bytes()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-message")
	req.Header.Set("content-type", "application/dns-message")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}
	sz, err := strconv.Atoi(resp.Header.Get("content-length"))
	if err != nil || sz < 0 || sz > 65535 {
		return nil, ErrDecodeError
	}
	body := make([]byte, sz)
	if _, err := io.ReadFull(resp.Body, body); err != nil {
		return nil, err
	}
	result, err := decodeDNSMessage(body)
	if err != nil {
		return nil, err
	}

	if rc := result.rCode; rc != 0 {
		if err := rcode[rc]; err != nil {
			return nil, fmt.Errorf("%s (%s): %w (%d)", name, typ, rcode[rc], rc)
		}
		return nil, fmt.Errorf("%s (%s): response code %d", name, typ, rc)
	}
	var res []any
	want := strings.TrimSuffix(name, ".")
	for _, a := range result.answer {
		name := strings.TrimSuffix(a.name, ".")
		if name == want && a.typ == rrTypes[typ] {
			res = append(res, a.data)
		}
		if name == want && a.typ == 5 { // CNAME
			want = strings.TrimSuffix(a.data.(string), ".")
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
