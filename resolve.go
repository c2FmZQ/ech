package ech

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/c2FmZQ/ech/dns"
)

const defaultResolverCacheSize = 32

var (
	ErrInvalidName = errors.New("invalid name")

	ErrFormatError       = errors.New("format error")
	ErrServerFailure     = errors.New("server failure")
	ErrNonExistentDomain = errors.New("non-existent domain")
	ErrNotImplemented    = errors.New("not implemented")
	ErrQueryRefused      = errors.New("query refused")

	rcode = map[uint16]error{
		1: ErrFormatError,
		2: ErrServerFailure,
		3: ErrNonExistentDomain,
		4: ErrNotImplemented,
		5: ErrQueryRefused,
	}

	timeNow = time.Now
)

// ResolveResult contains the A and HTTPS records.
type ResolveResult struct {
	Port       uint16
	Address    []net.IP
	HTTPS      []dns.HTTPS
	Additional map[string][]net.IP
}

type Target struct {
	Address netip.AddrPort
	ECH     []byte
	ALPN    []string
}

func (r ResolveResult) clone() ResolveResult {
	return ResolveResult{
		Port:       r.Port,
		Address:    slices.Clone(r.Address),
		HTTPS:      slices.Clone(r.HTTPS),
		Additional: maps.Clone(r.Additional),
	}
}

// Targets computes the target addresses to attempt in preferred order.
func (r ResolveResult) Targets(network string) iter.Seq[Target] {
	address := func(ip net.IP, port uint16) netip.AddrPort {
		if (network == "tcp4" || network == "udp4") && len(ip) != 4 {
			return netip.AddrPort{}
		}
		if (network == "tcp6" || network == "udp6") && len(ip) != 16 {
			return netip.AddrPort{}
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return netip.AddrPort{}
		}
		return netip.AddrPortFrom(addr, port)
	}
	return func(yield func(Target) bool) {
		seen := make(map[netip.AddrPort]bool)
		add := func(ip net.IP, port uint16, ech []byte, alpn []string) bool {
			if port == 0 {
				port = r.Port
			}
			addr := address(ip, port)
			if !addr.IsValid() {
				return true
			}
			if seen[addr] {
				return true
			}
			seen[addr] = true
			return yield(Target{Address: addr, ECH: ech, ALPN: alpn})
		}

		for _, h := range r.HTTPS {
			if h.Priority == 0 {
				continue
			}
			port := r.Port
			// When using HTTPS RRs, http requests are upgraded to
			// https. RFC 9460 section-9.5
			if port == 80 {
				port = 443
			}
			if h.Port > 0 {
				port = h.Port
			}
			alpn := h.ALPN
			if !h.NoDefaultALPN {
				alpn = append(alpn, "http/1.1")
			}
			if h.Target != "" {
				for _, a := range r.Additional[h.Target] {
					if !add(a, port, h.ECH, alpn) {
						return
					}
				}
				continue
			}
			for _, a := range r.Address {
				if !add(a, port, h.ECH, alpn) {
					return
				}
			}
			if len(r.Address) == 0 {
				for _, a := range h.IPv4Hint {
					if !add(a, port, h.ECH, alpn) {
						return
					}
				}
				for _, a := range h.IPv6Hint {
					if !add(a, port, h.ECH, alpn) {
						return
					}
				}
			}
		}
		if len(seen) > 0 {
			return
		}
		for _, a := range r.Address {
			if !add(a, r.Port, nil, nil) {
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
		cache:   newResolverCache(),
	}
}

// GoogleResolver uses Google's DNS-over-HTTPS service.
// https://developers.google.com/speed/public-dns/docs/doh
func GoogleResolver() *Resolver {
	return &Resolver{
		baseURL: url.URL{Scheme: "https", Host: "dns.google", Path: "/dns-query"},
		cache:   newResolverCache(),
	}
}

// WikimediaResolver uses Wikimedia's DNS-over-HTTPS service.
// https://meta.wikimedia.org/wiki/Wikimedia_DNS
func WikimediaResolver() *Resolver {
	return &Resolver{
		baseURL: url.URL{Scheme: "https", Host: "wikimedia-dns.org", Path: "/dns-query"},
		cache:   newResolverCache(),
	}
}

// InsecureGoResolver uses the default GO resolver. This option exists for
// testing purposes and for cases where DoH is not desired. It does NOT use
// HTTPS RRs.
func InsecureGoResolver() *Resolver {
	return &Resolver{
		insecureUseGoResolver: true,
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
		cache:   newResolverCache(),
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
	cache   *lru.TwoQueueCache[cacheKey, *cacheValue]

	insecureUseGoResolver bool
}

// SetCacheSize sets the size of the DNS cache. The default size is 32. A zero
// or negative value disables caching.
func (r *Resolver) SetCacheSize(n int) {
	if n <= 0 {
		r.cache = nil
		return
	}
	if r.cache == nil {
		r.cache = newResolverCache()
	}
	r.cache.Resize(n)
}

func newResolverCache() *lru.TwoQueueCache[cacheKey, *cacheValue] {
	c, err := lru.New2Q[cacheKey, *cacheValue](defaultResolverCacheSize)
	if err != nil {
		panic(err)
	}
	return c
}

type cacheKey struct {
	name string
	typ  string
}

type cacheValue struct {
	mu         sync.RWMutex
	expiration time.Time
	result     []any
}

// Resolve uses DNS-over-HTTPS to resolve name.
//
// The name argument can be any of:
//   - an IP address or a hostname
//   - an IP address or a hostname followed by a colon and a port number
//   - a fully qualified URI
//
// Resolve uses the scheme and port number to locate the correct HTTPS RR
// as specified in RFC 9460 section 2.3. When left unspecified, the default
// scheme and port values are https and 443, respectively.
//
// For example:
//   - example.com:8443 uses QNAME _8443._https.example.com
//   - foo://example.com:123 uses QNAME _123._foo.example.com
//   - example.com, example.com:433, example.com:80 all use QNAME example.com
//
// If the scheme is either http or https and the port is either 80 or 443, the
// QNAME used is always the hostname by itself, without _port and _service.
//
// A and AAAA RRs are looked up with just the hostname as QNAME.
func (r *Resolver) Resolve(ctx context.Context, name string) (ResolveResult, error) {
	result := ResolveResult{
		Port: 443,
	}
	scheme := "https"

	if u, err := url.Parse(name); err == nil && u.Scheme != "" && u.Host != "" {
		scheme = strings.ToLower(u.Scheme)
		if scheme == "http" {
			scheme = "https"
		}
		name = u.Host
	}
	if h, p, err := net.SplitHostPort(name); err == nil {
		if pp, err := strconv.ParseUint(p, 10, 16); err == nil {
			name = h
			if pp > 0 {
				result.Port = uint16(pp)
			}
		}
	}
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

	if r.insecureUseGoResolver {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
		if err != nil {
			return result, err
		}
		result.Address = make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				result.Address = append(result.Address, ipv4)
				continue
			}
			result.Address = append(result.Address, ip)
		}
		return result, nil
	}

	// https://www.rfc-editor.org/rfc/rfc9460.html#section-2.3
	svcbName := name
	if result.Port != 80 && result.Port != 443 {
		svcbName = fmt.Sprintf("_%d._%s.%s", result.Port, scheme, name)
	} else if scheme != "https" {
		svcbName = fmt.Sprintf("_%s.%s", scheme, name)
	}

	// First, resolve HTTPS Aliases.
	want := svcbName
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
		if err != nil && !errors.Is(err, ErrNonExistentDomain) {
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
				continue
			}
		}
	}
	if want == svcbName {
		want = name
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
	cache := r.cache
	if cache == nil {
		v, _, err := r.resolveOneNoCache(ctx, name, typ)
		return v, err
	}
	key := cacheKey{name, typ}
	v, ok := cache.Get(key)
	if !ok {
		v = &cacheValue{}
		cache.Add(key, v)
	}
	// fast path
	v.mu.RLock()
	exp, res := v.expiration, v.result
	v.mu.RUnlock()
	if !exp.IsZero() && timeNow().Before(exp) {
		return res, nil
	}

	// slow path
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.expiration.IsZero() && timeNow().Before(v.expiration) {
		return v.result, nil
	}
	res, ttl, err := r.resolveOneNoCache(ctx, name, typ)
	if err != nil {
		cache.Remove(key)
		return nil, err
	}
	if len(res) == 0 {
		ttl = 300
	}
	v.expiration = timeNow().Add(time.Second * time.Duration(ttl))
	v.result = res
	return res, nil
}

func (r *Resolver) resolveOneNoCache(ctx context.Context, name, typ string) ([]any, uint32, error) {
	qq := &dns.Message{
		ID: 0x0000,
		RD: 1,
		Question: []dns.Question{{
			Name:  name,
			Type:  dns.RRType(typ),
			Class: 1,
		}},
	}
	qq.AddPadding()

	result, err := dns.DoH(ctx, qq, r.baseURL.String())
	if err != nil {
		return nil, 0, err
	}

	if rc := result.ResponseCode(); rc != 0 {
		if err := rcode[rc]; err != nil {
			return nil, 0, fmt.Errorf("%s (%s): %w (%d)", name, typ, rcode[rc], rc)
		}
		return nil, 0, fmt.Errorf("%s (%s): response code %d", name, typ, rc)
	}
	var res []any
	var ttl uint32
	want := strings.TrimSuffix(name, ".")
	for _, a := range result.Answer {
		if ttl == 0 || ttl > a.TTL {
			ttl = a.TTL
		}
		name := strings.TrimSuffix(a.Name, ".")
		if name == want && a.Type == dns.RRType(typ) {
			res = append(res, a.Data)
		}
		if name == want && a.Type == 5 { // CNAME
			want = strings.TrimSuffix(a.Data.(string), ".")
			continue
		}
	}
	return res, ttl, nil
}
