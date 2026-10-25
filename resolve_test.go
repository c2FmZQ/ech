package ech

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/ech/dns"
	"github.com/c2FmZQ/ech/testutil"
)

func TestResolve(t *testing.T) {
	ts := testutil.StartTestDNSServer(t, []dns.RR{
		// example.com A 192.168.0.1
		//               192.168.0.2
		{
			Name: "example.com", Type: 1, Class: 1, TTL: 60,
			Data: net.IP{192, 168, 0, 1},
		},
		{
			Name: "example.com", Type: 1, Class: 1, TTL: 60,
			Data: net.IP{192, 168, 0, 2},
		},
		// example.com HTTPS Alias www.example.com
		{
			Name: "example.com", Type: 65, Class: 1, TTL: 60,
			Data: dns.HTTPS{Priority: 0, Target: "www.example.com"},
		},
		// www.example.com A 192.168.0.3
		{
			Name: "www.example.com", Type: 1, Class: 1, TTL: 60,
			Data: net.IP{192, 168, 0, 3},
		},
		// www2.example.com CNAME www.example.com
		{
			Name: "www2.example.com", Type: 5, Class: 1, TTL: 60,
			Data: "www.example.com",
		},
		// foo.example.com HTTPS . alpn=h2 port=8443 ipv4hint=127.0.0.1
		{
			Name: "foo.example.com", Type: 65, Class: 1, TTL: 60,
			Data: dns.HTTPS{Priority: 1, ALPN: []string{"h2"}, Port: 8443, IPv4Hint: []net.IP{{127, 0, 0, 1}}},
		},
		// bar.example.com A 192.168.0.4
		{
			Name: "bar.example.com", Type: 1, Class: 1, TTL: 60,
			Data: net.IP{192, 168, 0, 4},
		},
		// bar.example.com HTTPS . alpn=h2 ech=...
		{
			Name: "bar.example.com", Type: 65, Class: 1, TTL: 60,
			Data: dns.HTTPS{Priority: 1, ALPN: []string{"h2"}, ECH: []byte{0, 1, 2}},
		},
		// xxx.example.com HTTPS example.com alpn=h2 ech=...
		{
			Name: "xxx.example.com", Type: 65, Class: 1, TTL: 60,
			Data: dns.HTTPS{Priority: 1, Target: "example.com", ALPN: []string{"h2"}, ECH: []byte{0, 1, 2}},
		},
		// yyy.example.com A 192.168.0.5
		{
			Name: "yyy.example.com", Type: 1, Class: 1, TTL: 60,
			Data: net.IP{192, 168, 0, 5},
		},
		// yyy.example.com HTTPS example.com alpn=h2 ech=...
		{
			Name: "yyy.example.com", Type: 65, Class: 1, TTL: 60,
			Data: dns.HTTPS{Priority: 1, Target: "example.com", ALPN: []string{"h2"}, ECH: []byte{0, 1, 2}},
		},
		// _8443._foo.api.example.com. 7200 IN SVCB 0 svc4.example.net.
		{
			Name: "_8443._foo.api.example.com", Type: 65, Class: 1, TTL: 7200,
			Data: dns.HTTPS{Priority: 0, Target: "svc4.example.net"},
		},
		// svc4.example.net.  7200  IN SVCB 3 svc4.example.net. alpn="bar" port="8004"
		{
			Name: "svc4.example.net", Type: 65, Class: 1, TTL: 7200,
			Data: dns.HTTPS{Priority: 3, Target: "svc4.example.net", ALPN: []string{"bar"}, Port: 8004},
		},
		{
			Name: "svc4.example.net", Type: 1, Class: 1, TTL: 60,
			Data: net.IP{10, 10, 10, 1},
		},
	})
	defer ts.Close()
	resolver := &Resolver{baseURL: url.URL{Scheme: "http", Host: ts.Listener.Addr().String(), Path: "/dns-query"}}

	for _, tc := range []struct {
		name string
		want ResolveResult
	}{
		{
			name: "www.example.com",
			want: ResolveResult{
				Port:    443,
				Address: []net.IP{{192, 168, 0, 3}},
			},
		},
		{
			name: "example.com",
			want: ResolveResult{
				Port:    443,
				Address: []net.IP{{192, 168, 0, 3}},
			},
		},
		{
			name: "www2.example.com",
			want: ResolveResult{
				Port:    443,
				Address: []net.IP{{192, 168, 0, 3}},
			},
		},
		{
			name: "foo.example.com",
			want: ResolveResult{
				Port: 443,
				HTTPS: []dns.HTTPS{{
					Priority: 1, ALPN: []string{"h2"}, Port: 8443, IPv4Hint: []net.IP{{127, 0, 0, 1}},
				}},
			},
		},
		{
			name: "bar.example.com",
			want: ResolveResult{
				Port:    443,
				Address: []net.IP{{192, 168, 0, 4}},
				HTTPS: []dns.HTTPS{{
					Priority: 1, ALPN: []string{"h2"}, ECH: []byte{0, 1, 2},
				}},
			},
		},
		{
			name: "xxx.example.com",
			want: ResolveResult{
				Port: 443,
				HTTPS: []dns.HTTPS{{
					Priority: 1, Target: "example.com", ALPN: []string{"h2"}, ECH: []byte{0, 1, 2},
				}},
				Additional: map[string][]net.IP{
					"example.com": []net.IP{{192, 168, 0, 1}, {192, 168, 0, 2}},
				},
			},
		},
		{
			name: "yyy.example.com",
			want: ResolveResult{
				Port:    443,
				Address: []net.IP{{192, 168, 0, 5}},
				HTTPS: []dns.HTTPS{{
					Priority: 1, Target: "example.com", ALPN: []string{"h2"}, ECH: []byte{0, 1, 2},
				}},
				Additional: map[string][]net.IP{
					"example.com": []net.IP{{192, 168, 0, 1}, {192, 168, 0, 2}},
				},
			},
		},
		{
			name: "foo://api.example.com:8443",
			want: ResolveResult{
				Port:    8443,
				Address: []net.IP{{10, 10, 10, 1}},
				HTTPS: []dns.HTTPS{{
					Priority: 3, Target: "svc4.example.net", ALPN: []string{"bar"}, Port: 8004,
				}},
				Additional: map[string][]net.IP{
					"svc4.example.net": []net.IP{{10, 10, 10, 1}},
				},
			},
		},
	} {
		got, err := resolver.Resolve(t.Context(), tc.name)
		if err != nil {
			t.Fatalf("resolver.Resolve: %v", err)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Resolve(%q) = %#v, want %#v", tc.name, got, tc.want)
		}
	}
}

func TestResolverCache(t *testing.T) {
	now := time.Date(2025, 2, 25, 12, 0, 0, 0, time.UTC)
	timeNow = func() time.Time {
		return now
	}

	db := []dns.RR{
		{
			Name: "example.com", Type: 1, Class: 1, TTL: 5,
			Data: net.IP{192, 168, 0, 1},
		},
		{
			Name: "example.com", Type: 1, Class: 1, TTL: 5,
			Data: net.IP{192, 168, 0, 2},
		},
	}
	ts := testutil.StartTestDNSServer(t, db)
	defer ts.Close()
	resolver := &Resolver{baseURL: url.URL{Scheme: "http", Host: ts.Listener.Addr().String(), Path: "/dns-query"}}
	resolver.SetCacheSize(10)

	want := []any{net.IP{192, 168, 0, 1}, net.IP{192, 168, 0, 2}}

	for range 5 {
		got, err := resolver.resolveOne(t.Context(), "example.com", "A")
		if err != nil {
			t.Fatalf("resolver.resolveOne: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("resolver.resolveOne() = %#v, want %#v", got, want)
		}
		now = now.Add(time.Second)
		db[0].Data = net.IP{192, 168, 1, 1}
		db[1].Data = net.IP{192, 168, 1, 2}
	}

	want = []any{net.IP{192, 168, 1, 1}, net.IP{192, 168, 1, 2}}

	for range 5 {
		got, err := resolver.resolveOne(t.Context(), "example.com", "A")
		if err != nil {
			t.Fatalf("resolver.resolveOne: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("resolver.resolveOne() = %#v, want %#v", got, want)
		}
		now = now.Add(time.Second)
		db[0].Name = "foo.example.com"
		db[1].Name = "foo.example.com"
	}

	want = nil

	for range 5 {
		got, err := resolver.resolveOne(t.Context(), "example.com", "A")
		if err != nil {
			t.Fatalf("resolver.resolveOne: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("resolver.resolveOne() = %#v, want %#v", got, want)
		}
	}
}

func TestResolveResultTargets(t *testing.T) {
	for i, tc := range []struct {
		result ResolveResult
		want   string
	}{
		{
			result: ResolveResult{
				Port:    443,
				Address: []net.IP{{192, 168, 0, 1}},
			},
			want: "192.168.0.1:443",
		},
		{
			result: ResolveResult{
				Port:    443,
				Address: []net.IP{{192, 168, 0, 1}, {192, 168, 0, 2}},
			},
			want: "192.168.0.1:443 | 192.168.0.2:443",
		},
		{
			result: ResolveResult{
				Port:    443,
				Address: []net.IP{{192, 168, 0, 1}, {192, 168, 0, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
			},
			want: "192.168.0.1:443 | 192.168.0.2:443 | [::1]:443",
		},
		{
			result: ResolveResult{
				Port:    443,
				Address: []net.IP{{192, 168, 0, 5}},
				HTTPS: []dns.HTTPS{{
					Priority: 1, Target: "example.com", ALPN: []string{"h2"}, ECH: []byte("xyz"),
				}},
				Additional: map[string][]net.IP{
					"example.com": []net.IP{{192, 168, 0, 1}, {192, 168, 0, 2}},
				},
			},
			want: "192.168.0.1:443 xyz | 192.168.0.2:443 xyz",
		},
		{
			result: ResolveResult{
				Port: 443,
				HTTPS: []dns.HTTPS{{
					Priority: 1, ALPN: []string{"h2"}, IPv4Hint: []net.IP{{192, 168, 0, 1}}, ECH: []byte("xyz"),
				}},
			},
			want: "192.168.0.1:443 xyz",
		},
		{
			result: ResolveResult{
				Port: 443,
				HTTPS: []dns.HTTPS{{
					Priority: 1, Target: "foo", ALPN: []string{"h2"}, Port: 8443, IPv4Hint: []net.IP{{192, 168, 0, 1}}, ECH: []byte("xyz"),
				}},
				Additional: map[string][]net.IP{
					"foo": []net.IP{{192, 168, 0, 2}},
				},
			},
			want: "192.168.0.2:8443 xyz",
		},
		{
			result: ResolveResult{
				Port:    8443,
				Address: []net.IP{{10, 10, 10, 1}},
				HTTPS: []dns.HTTPS{{
					Priority: 3, Target: "svc4.example.net", ALPN: []string{"bar"}, Port: 8004,
				}},
				Additional: map[string][]net.IP{
					"svc4.example.net": []net.IP{{10, 10, 10, 1}},
				},
			},
			want: "10.10.10.1:8004",
		},
	} {
		var s []string
		for target := range tc.result.Targets("tcp") {
			v := target.Address.String()
			if len(target.ECH) > 0 {
				v += " " + string(target.ECH)
			}
			s = append(s, v)
		}
		got := strings.Join(s, " | ")
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("[%d] Got %#v, want %#v", i, got, tc.want)
		}
	}
}

func TestResolveTargetsConcurrentALPN(t *testing.T) {
	ts := testutil.StartTestDNSServer(t, []dns.RR{
		{
			Name: "example.com", Type: 1, Class: 1, TTL: 60,
			Data: net.IP{192, 168, 0, 1},
		},
		{
			Name: "example.com", Type: 65, Class: 1, TTL: 60,
			Data: dns.HTTPS{
				Priority:      1,
				ALPN:          []string{"h3", "h2", "foo"},
				NoDefaultALPN: false,
				ECH:           []byte{1, 2, 3},
			},
		},
	})
	defer ts.Close()

	resolver := &Resolver{
		baseURL: url.URL{Scheme: "http", Host: ts.Listener.Addr().String(), Path: "/dns-query"},
		cache:   newResolverCache(),
	}

	wantALPN := []string{"h3", "h2", "foo", "http/1.1"}
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				res, err := resolver.Resolve(t.Context(), "example.com")
				if err != nil {
					t.Errorf("Resolve: %v", err)
					return
				}
				for _, r := range []ResolveResult{res, res.clone()} {
					for target := range r.Targets("tcp") {
						if !slices.Equal(target.ALPN, wantALPN) {
							t.Errorf("target.ALPN = %v, want %v", target.ALPN, wantALPN)
							return
						}
					}
				}
			}
		}()
	}
	wg.Wait()
}

func TestResolveInvalidSchemeAndSVCBName(t *testing.T) {
	ts := testutil.StartTestDNSServer(t, nil)
	defer ts.Close()
	resolver := &Resolver{
		baseURL: url.URL{Scheme: "http", Host: ts.Listener.Addr().String(), Path: "/dns-query"},
	}

	longHost := fmt.Sprintf("%s.%s.%s.%s.example.com",
		strings.Repeat("a", 60),
		strings.Repeat("b", 60),
		strings.Repeat("c", 60),
		strings.Repeat("d", 55),
	) // 60+1+60+1+60+1+55+1+11 = 249 bytes (<= 253), but with _8443._https. prefix it exceeds 255.

	for _, name := range []string{
		strings.Repeat("a", 63) + "://example.com",
		strings.Repeat("a", 300) + "://example.com:8443",
		"https://" + longHost + ":8443",
	} {
		if _, err := resolver.Resolve(t.Context(), name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Resolve(%q) = %v, want ErrInvalidName", name, err)
		}
	}
}

func TestResolveOutOfOrderCNAME(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer req.Body.Close()
		body, _ := io.ReadAll(req.Body)
		qq, err := dns.DecodeMessage(body)
		if err != nil {
			t.Errorf("dns.DecodeMessage: %v", err)
			return
		}
		qq.QR = 1
		q := qq.Question[0]
		switch q.Name {
		case "alias.example.com":
			if q.Type == 1 {
				// Return A record BEFORE CNAME record, and multi-hop CNAMEs in reverse order.
				qq.Answer = []dns.RR{
					{Name: "target.example.com", Type: 1, Class: 1, TTL: 60, Data: net.IP{192, 168, 0, 99}},
					{Name: "mid.example.com", Type: 5, Class: 1, TTL: 60, Data: "target.example.com"},
					{Name: "alias.example.com", Type: 5, Class: 1, TTL: 60, Data: "mid.example.com"},
				}
			}
		case "loop.example.com":
			qq.Answer = []dns.RR{
				{Name: "loop2.example.com", Type: 5, Class: 1, TTL: 60, Data: "loop.example.com"},
				{Name: "loop.example.com", Type: 5, Class: 1, TTL: 60, Data: "loop2.example.com"},
			}
		}
		w.Write(qq.Bytes())
	}))
	defer ts.Close()

	resolver := &Resolver{
		baseURL: url.URL{Scheme: "http", Host: ts.Listener.Addr().String(), Path: "/dns-query"},
	}

	got, err := resolver.Resolve(t.Context(), "alias.example.com")
	if err != nil {
		t.Fatalf("Resolve(alias.example.com): %v", err)
	}
	want := ResolveResult{
		Port:    443,
		Address: []net.IP{{192, 168, 0, 99}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Resolve(alias.example.com) = %#v, want %#v", got, want)
	}

	gotLoop, err := resolver.Resolve(t.Context(), "loop.example.com")
	if err != nil {
		t.Fatalf("Resolve(loop.example.com): %v", err)
	}
	if len(gotLoop.Address) != 0 {
		t.Errorf("Resolve(loop.example.com) Address = %v, want empty", gotLoop.Address)
	}
}
