package ech

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// ResolveResult contains the A and HTTPS records.
type ResolveResult struct {
	Address []string
	HTTPS   []HTTPS
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

// Resolve uses DNS-over-HTTPS to resolve name. It uses Cloudflare's public
// server 1.1.1.1. https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/
func Resolve(ctx context.Context, name string) (ResolveResult, error) {
	a, err := resolveOne(ctx, name, "A")
	if err != nil {
		return ResolveResult{}, err
	}
	result := ResolveResult{
		Address: a,
	}
	raw, err := resolveOne(ctx, name, "HTTPS")
	if err != nil {
		return result, err
	}
	for _, h := range raw {
		v, err := parseHTTPS(h)
		if err != nil {
			return result, err
		}
		result.HTTPS = append(result.HTTPS, v)
	}
	return result, nil
}

type dohResult struct {
	Status int    `json:"Status"`
	Error  string `json:"error"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"ttl"`
		Data string `json:"data"`
	} `json:"Answer"`
}

var (
	rrTypes = map[string]int{
		"A":     1,
		"CNAME": 5,
		"HTTPS": 65,
	}
	rcode = map[int]string{
		0: "No Error",
		1: "Format Error",
		2: "Server Failure",
		3: "Non-Existent Domain",
		4: "Not Implemented",
		5: "Query Refused",
	}
)

func resolveOne(ctx context.Context, name, typ string) ([]string, error) {
	u := url.URL{Scheme: "https", Host: "1.1.1.1", Path: "/dns-query"}
	q := u.Query()
	q.Set("name", name)
	q.Set("type", typ)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result dohResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if e := result.Error; e != "" {
		return nil, fmt.Errorf("%s (%s): %v", name, typ, e)
	}
	if rc := result.Status; rc != 0 {
		return nil, fmt.Errorf("%s (%s): %s (%d)", name, typ, rcode[rc], rc)
	}
	var res []string
	want := name
	for _, a := range result.Answer {
		if a.Name == want && a.Type == rrTypes[typ] {
			res = append(res, a.Data)
		}
		if a.Name == want && a.Type == 5 { // CNAME
			want = a.Data
			continue
		}
	}
	return res, nil
}

func parseHTTPS(v string) (HTTPS, error) {
	var result HTTPS
	if !strings.HasPrefix(v, "\\# ") {
		return result, ErrDecodeError
	}
	v = v[3:]
	space := strings.Index(v, " ")
	if space < 0 {
		return result, ErrDecodeError
	}
	length, err := strconv.Atoi(v[:space])
	if err != nil {
		return result, err
	}
	v = strings.ReplaceAll(v[space:], " ", "")
	b, err := hex.DecodeString(v)
	if err != nil {
		return result, err
	}
	if len(b) != length {
		return result, ErrDecodeError
	}
	s := cryptobyte.String(b)
	var svcPriority uint16
	if !s.ReadUint16(&svcPriority) {
		return result, ErrDecodeError
	}
	result.Priority = svcPriority
	var nameParts []string
	for {
		var name cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&name) {
			return result, ErrDecodeError
		}
		if len(name) == 0 {
			break
		}
		nameParts = append(nameParts, string(name))
	}
	result.Target = strings.Join(nameParts, ".")
	for !s.Empty() {
		var key uint16
		if !s.ReadUint16(&key) {
			return result, ErrDecodeError
		}
		var value cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&value) {
			return result, ErrDecodeError
		}
		switch key {
		case 0: // mandatory keys
		case 1: // alpn
			for !value.Empty() {
				var proto cryptobyte.String
				if !value.ReadUint8LengthPrefixed(&proto) {
					return result, ErrDecodeError
				}
				result.ALPN = append(result.ALPN, string(proto))
			}
		case 2: // no-default-alpn
			result.NoDefaultALPN = true
		case 3: // port
			if !value.ReadUint16(&result.Port) {
				return result, ErrDecodeError
			}
		case 4: // ipv4hint
			result.IPv4Hint = net.IP(value)
		case 5: // ECH
			result.ECH = value
		case 6: // ipv6hint
			result.IPv6Hint = net.IP(value)
		}
	}
	return result, nil
}
