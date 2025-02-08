package ech

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"log"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/c2FmZQ/ech/dns"
)

var (
	ErrInvalidName = errors.New("invalid name")

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

// ResolveResult contains the A and HTTPS records.
type ResolveResult struct {
	Address    []net.IP
	HTTPS      []dns.HTTPS
	Additional map[string][]net.IP
}

type Target struct {
	Address net.Addr
	ECH     []byte
}

// Targets computes the target addresses to attempt in preferred order.
func (r ResolveResult) Targets(network string, defaultPort int) iter.Seq[Target] {
	address := func(ip net.IP, port int) net.Addr {
		if (network == "tcp4" || network == "udp4") && len(ip) != 4 {
			return nil
		}
		if (network == "tcp6" || network == "udp6") && len(ip) != 16 {
			return nil
		}
		switch network {
		case "tcp", "tcp4", "tcp6":
			return &net.TCPAddr{IP: ip, Port: port}
		case "udp", "udp4", "udp6":
			return &net.UDPAddr{IP: ip, Port: port}
		default:
			return nil
		}
	}
	return func(yield func(Target) bool) {
		seen := make(map[string]bool)
		add := func(ip net.IP, port int, ech []byte) bool {
			addr := address(ip, port)
			if addr == nil {
				return true
			}
			key := addr.String() + " " + hex.EncodeToString(ech)
			if seen[key] {
				return true
			}
			seen[key] = true
			return yield(Target{Address: addr, ECH: ech})
		}

		for _, h := range r.HTTPS {
			port := defaultPort
			if h.Port > 0 {
				port = int(h.Port)
			}
			for _, a := range h.IPv4Hint {
				if !add(a, port, h.ECH) {
					return
				}
			}
			for _, a := range h.IPv6Hint {
				if !add(a, port, h.ECH) {
					return
				}
			}
			if h.Target != "" {
				for _, a := range r.Additional[h.Target] {
					if !add(a, port, h.ECH) {
						return
					}
				}
				continue
			}
			for _, a := range r.Address {
				if !add(a, port, h.ECH) {
					return
				}
			}
		}
		for _, a := range r.Address {
			if !add(a, defaultPort, nil) {
				return
			}
		}
	}
}

// Resolve is an alias for [Resolver.Resolve] with [DefaultResolver].
func Resolve(ctx context.Context, name string) (ResolveResult, error) {
	return DefaultResolver.Resolve(ctx, name)
}

// DefaultResolver is used by [Resolve], [Dial] and [github.com/c2FmZQ/ech/quic.Dial].
var DefaultResolver = CloudflareResolver()

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
	if u.Scheme != "https" && u.Hostname() != "127.0.0.1" {
		return nil, errors.New("service url must use https")
	}
	return &Resolver{
		baseURL: *u,
	}, nil
}

// Resolver is a RFC 8484 DNS-over-HTTPS (DoH) client.
//
// The resolver uses HTTPS DNS Resource Records whenever possible to retrieve
// the service's current Encrypted Client Hello (ECH) ConfigList. It also
// follows the RFC 9460 specifications to interpret the other HTTPS RR fields.
//
// The [ResolveResult] contains all the IP addresses, and final HTTPS records
// needed to establish a secure and private TLS connection using ECH.
type Resolver struct {
	baseURL url.URL
}

// Resolve uses DNS-over-HTTPS to resolve name.
func (r *Resolver) Resolve(ctx context.Context, name string) (ResolveResult, error) {
	result := ResolveResult{}
	if name == "localhost" {
		result.Address = []net.IP{
			net.IP{127, 0, 0, 1},
			net.IPv6loopback,
		}
		return result, nil
	}
	if ip := net.ParseIP(name); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			result.Address = []net.IP{ipv4}
		} else {
			result.Address = []net.IP{ip}
		}
		return result, nil
	}
	if len(name) > 255 {
		return result, ErrInvalidName
	}
	for _, p := range strings.Split(name, ".") {
		if len(p) > 63 {
			return result, ErrInvalidName
		}
	}

	// First, resolve HTTPS Aliases.
	want := name
	seen := make(map[string]bool)
	for {
		if seen[want] {
			log.Printf("ERR Resolve(%q): alias loop detected", name)
			want = name
			break
		}
		seen[want] = true
		if len(seen) >= 5 {
			log.Printf("ERR Resolve(%q): alias chain too long", name)
			want = name
			break
		}
		https, err := r.resolveOne(ctx, want, "HTTPS")
		if err != nil {
			return result, err
		}
		if len(https) > 0 {
			// Alias Mode: Priority = 0
			v := https[0].(dns.HTTPS)
			if v.Priority == 0 && len(v.Target) == 0 {
				result.HTTPS = nil
				break
			}
			if v.Priority == 0 {
				// Follow aliases. RFC 9460 2.4.2
				want = v.Target
				result.HTTPS = nil
				continue
			}
		}
		for _, v := range https {
			result.HTTPS = append(result.HTTPS, v.(dns.HTTPS))
		}
		sort.Slice(result.HTTPS, func(i, j int) bool {
			return result.HTTPS[i].Priority < result.HTTPS[j].Priority
		})
		break
	}
	// Then, resolve Service Mode Targets.
	for _, h := range result.HTTPS {
		if h.Priority == 0 {
			continue
		}
		if len(h.Target) > 0 {
			if err := r.resolveTarget(ctx, h.Target, &result); err != nil {
				return result, err
			}
		}
	}
	// Then, resolve IP addresses.
	a, err := r.resolveOne(ctx, want, "A")
	if err != nil {
		return result, err
	}
	for _, v := range a {
		result.Address = append(result.Address, v.(net.IP))
	}
	aaaa, err := r.resolveOne(ctx, want, "AAAA")
	if err != nil {
		return result, err
	}
	for _, v := range aaaa {
		result.Address = append(result.Address, v.(net.IP))
	}
	return result, nil
}

func (r *Resolver) resolveTarget(ctx context.Context, name string, res *ResolveResult) error {
	if res.Additional == nil {
		res.Additional = make(map[string][]net.IP)
	}
	if _, exists := res.Additional[name]; exists {
		return nil
	}
	a, err := r.resolveOne(ctx, name, "A")
	if err != nil {
		return err
	}
	for _, v := range a {
		res.Additional[name] = append(res.Additional[name], v.(net.IP))
	}
	aaaa, err := r.resolveOne(ctx, name, "AAAA")
	if err != nil {
		return err
	}
	for _, v := range aaaa {
		res.Additional[name] = append(res.Additional[name], v.(net.IP))
	}
	return nil
}

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
