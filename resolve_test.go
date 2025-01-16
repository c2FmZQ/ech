package ech

import (
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"

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
				Address: []net.IP{{192, 168, 0, 3}},
			},
		},
		{
			name: "example.com",
			want: ResolveResult{
				Address: []net.IP{{192, 168, 0, 3}},
			},
		},
		{
			name: "www2.example.com",
			want: ResolveResult{
				Address: []net.IP{{192, 168, 0, 3}},
			},
		},
		{
			name: "foo.example.com",
			want: ResolveResult{
				HTTPS: []dns.HTTPS{{
					Priority: 1, ALPN: []string{"h2"}, Port: 8443, IPv4Hint: []net.IP{{127, 0, 0, 1}},
				}},
			},
		},
		{
			name: "bar.example.com",
			want: ResolveResult{
				Address: []net.IP{{192, 168, 0, 4}},
				HTTPS: []dns.HTTPS{{
					Priority: 1, ALPN: []string{"h2"}, ECH: []byte{0, 1, 2},
				}},
			},
		},
		{
			name: "xxx.example.com",
			want: ResolveResult{
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
				Address: []net.IP{{192, 168, 0, 5}},
				HTTPS: []dns.HTTPS{{
					Priority: 1, Target: "example.com", ALPN: []string{"h2"}, ECH: []byte{0, 1, 2},
				}},
				Additional: map[string][]net.IP{
					"example.com": []net.IP{{192, 168, 0, 1}, {192, 168, 0, 2}},
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

func TestResolveResultTargets(t *testing.T) {
	for i, tc := range []struct {
		result ResolveResult
		want   string
	}{
		{
			result: ResolveResult{
				Address: []net.IP{{192, 168, 0, 1}},
			},
			want: "192.168.0.1:443",
		},
		{
			result: ResolveResult{
				Address: []net.IP{{192, 168, 0, 1}, {192, 168, 0, 2}},
			},
			want: "192.168.0.1:443 | 192.168.0.2:443",
		},
		{
			result: ResolveResult{
				Address: []net.IP{{192, 168, 0, 1}, {192, 168, 0, 2}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
			},
			want: "192.168.0.1:443 | 192.168.0.2:443 | [::1]:443",
		},
		{
			result: ResolveResult{
				Address: []net.IP{{192, 168, 0, 5}},
				HTTPS: []dns.HTTPS{{
					Priority: 1, Target: "example.com", ALPN: []string{"h2"}, ECH: []byte("xyz"),
				}},
				Additional: map[string][]net.IP{
					"example.com": []net.IP{{192, 168, 0, 1}, {192, 168, 0, 2}},
				},
			},
			want: "192.168.0.1:443 xyz | 192.168.0.2:443 xyz | 192.168.0.5:443",
		},
		{
			result: ResolveResult{
				HTTPS: []dns.HTTPS{{
					Priority: 1, ALPN: []string{"h2"}, IPv4Hint: []net.IP{{192, 168, 0, 1}}, ECH: []byte("xyz"),
				}},
			},
			want: "192.168.0.1:443 xyz",
		},
		{
			result: ResolveResult{
				HTTPS: []dns.HTTPS{{
					Priority: 1, Target: "foo", ALPN: []string{"h2"}, Port: 8443, IPv4Hint: []net.IP{{192, 168, 0, 1}}, ECH: []byte("xyz"),
				}},
				Additional: map[string][]net.IP{
					"foo": []net.IP{{192, 168, 0, 2}},
				},
			},
			want: "192.168.0.1:8443 xyz | 192.168.0.2:8443 xyz",
		},
	} {
		var s []string
		for _, target := range tc.result.Targets("tcp", 443) {
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
