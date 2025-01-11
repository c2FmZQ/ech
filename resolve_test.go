package ech

import (
	"net"
	"reflect"
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

func TestParseHTTPS(t *testing.T) {
	var (
		values = []string{
			`12 foo. alpn=h3,h2 no-default-alpn port=1234 ipv4hint=127.0.0.1 ech=AE3+DQBJAAAgACAqK23W2Hxj3kCId9Ah1rE7EyBsFyVaUl1wTL/cEUFEQQAMAAEAAwABAAIAAQABIhJwdWJsaWMuZXhhbXBsZS5jb20AAA== ipv6hint=::1`,
			`\# 138 00 0c 03 66 6f 6f 00 00 01 00 06 02 68 33 02 68 32 00 02 00 00 00 03 00 02 04 d2 00 04 00 04 7f 00 00 01 00 05 00 4f 00 4d fe 0d 00 49 00 00 20 00 20 2a 2b 6d d6 d8 7c 63 de 40 88 77 d0 21 d6 b1 3b 13 20 6c 17 25 5a 52 5d 70 4c bf dc 11 41 44 41 00 0c 00 01 00 03 00 01 00 02 00 01 00 01 22 12 70 75 62 6c 69 63 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 00 00 00 06 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01`,
		}
		want = HTTPS{
			Priority:      12,
			Target:        "foo",
			ALPN:          []string{"h3", "h2"},
			NoDefaultALPN: true,
			Port:          1234,
			IPv4Hint:      net.IP{127, 0, 0, 1},
			IPv6Hint:      net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			ECH: []uint8{
				0x00, 0x4d, 0xfe, 0x0d, 0x00, 0x49, 0x00, 0x00, 0x20, 0x00, 0x20, 0x2a, 0x2b, 0x6d, 0xd6, 0xd8,
				0x7c, 0x63, 0xde, 0x40, 0x88, 0x77, 0xd0, 0x21, 0xd6, 0xb1, 0x3b, 0x13, 0x20, 0x6c, 0x17, 0x25,
				0x5a, 0x52, 0x5d, 0x70, 0x4c, 0xbf, 0xdc, 0x11, 0x41, 0x44, 0x41, 0x00, 0x0c, 0x00, 0x01, 0x00,
				0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x22, 0x12, 0x70, 0x75, 0x62, 0x6c, 0x69,
				0x63, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
			},
		}
	)
	for _, v := range values {
		got, err := parseHTTPS(v)
		if err != nil {
			t.Errorf("parseHTTPS(%q) failed: %v", v, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parseHTTPS(%q) = %#v, want %#v", v, got, want)
		}
	}
}
