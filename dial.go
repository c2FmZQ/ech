package ech

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// Dial connects to the given network and address using [net.Dialer] and
// [tls.Client]. Name resolution is done with [Resolve] and
// EncryptedClientHelloConfigList will be set automatically if the hostname has
// a HTTPS DNS record with ech.
func Dial(ctx context.Context, network, addr string, tc *tls.Config) (*tls.Conn, error) {
	if tc != nil {
		tc = tc.Clone()
	} else {
		tc = &tls.Config{}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}
	result, err := Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var ipv4, ipv6 bool
	switch network {
	case "tcp":
		ipv4 = true
		ipv6 = true
	case "tcp4":
		ipv4 = true
	case "tcp6":
		ipv6 = true
	default:
		return nil, errors.New("network must be one of tcp, tcp4, tcp6")
	}
	var ipaddr []net.IP
	if ipv4 {
		if n := len(result.A); n > 0 {
			ipaddr = append(ipaddr, result.A...)
		} else {
			for _, h := range result.HTTPS {
				if len(h.IPv4Hint) > 0 {
					ipaddr = append(ipaddr, h.IPv4Hint)
				}
			}
		}
	}
	if ipv6 {
		if n := len(result.AAAA); n > 0 {
			ipaddr = append(ipaddr, result.AAAA...)
		} else {
			for _, h := range result.HTTPS {
				if len(h.IPv6Hint) > 0 {
					ipaddr = append(ipaddr, h.IPv6Hint)
				}
			}
		}
	}
	if len(ipaddr) == 0 {
		return nil, errors.New("no address")
	}
	if tc.ServerName == "" {
		tc.ServerName = host
	}
	if tc.EncryptedClientHelloConfigList == nil {
		tc.EncryptedClientHelloConfigList = result.ECH()
	}
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("cannot use go resolver")
			},
		},
	}
	var errs []error
	for _, addr := range ipaddr {
	retry:
		ctx := ctx
		cancel := context.CancelFunc(nil)
		if len(ipaddr) > 1 {
			ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if cancel != nil {
			cancel()
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		tlsConn := tls.Client(conn, tc)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			var echErr *tls.ECHRejectionError
			if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
				tc.EncryptedClientHelloConfigList = echErr.RetryConfigList
				goto retry
			}
			errs = append(errs, err)
			continue
		}
		return tlsConn, nil
	}
	return nil, errors.Join(errs...)
}
