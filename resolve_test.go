package ech

import (
	"testing"
)

func TestReadToken(t *testing.T) {
	for _, tc := range []struct {
		line, token, rest string
	}{
		{`a b c`, "a", "b c"},
		{`a=b b=c`, "a=b", "b=c"},
		{`a="b b=c"`, "a=b b=c", ""},
		{`a="b b=c`, "a=b b=c", ""},
		{`a="b b=c`, "a=b b=c", ""},
		{`12 foo. alpn=h3,h2 no-default-alpn port=1234 ipv4hint=1.2.3.4 ech=AEf== ipv6hint=::1`, "12", "foo. alpn=h3,h2 no-default-alpn port=1234 ipv4hint=1.2.3.4 ech=AEf== ipv6hint=::1"},
		{`foo. alpn=h3,h2 no-default-alpn port=1234 ipv4hint=1.2.3.4 ech=AEf== ipv6hint=::1`, "foo.", "alpn=h3,h2 no-default-alpn port=1234 ipv4hint=1.2.3.4 ech=AEf== ipv6hint=::1"},
		{`port=1234 ipv4hint=1.2.3.4 ech=AEf== ipv6hint=::1`, "port=1234", "ipv4hint=1.2.3.4 ech=AEf== ipv6hint=::1"},
		{`ipv4hint=1.2.3.4 ech=AEf== ipv6hint=::1`, "ipv4hint=1.2.3.4", "ech=AEf== ipv6hint=::1"},
		{`ech=AEf== ipv6hint=::1`, "ech=AEf==", "ipv6hint=::1"},
		{`ipv6hint=::1`, "ipv6hint=::1", ""},
	} {
		token, rest := readToken(tc.line)
		if token != tc.token || rest != tc.rest {
			t.Errorf("readToken(%q) = %q, %q, want %q, %q", tc.line, token, rest, tc.token, tc.rest)
		}
	}
}
