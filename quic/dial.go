package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/c2FmZQ/ech"
	"github.com/quic-go/quic-go"
)

// Dial connects to the given network and address using [quic.DialAddr]. Name
// resolution is done with [Resolve] and EncryptedClientHelloConfigList will
// be set automatically if the hostname has a HTTPS DNS record with ech.
func Dial(ctx context.Context, network, addr string, tc *tls.Config, qc *quic.Config) (quic.Connection, error) {
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
	result, err := ech.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var ipv4, ipv6 bool
	switch network {
	case "udp":
		ipv4 = true
		ipv6 = true
	case "udp4":
		ipv4 = true
	case "udp6":
		ipv6 = true
	default:
		return nil, errors.New("network must be one of udp, udp4, udp6")
	}
	var ipaddr []string
	if ipv4 {
		if n := len(result.A); n > 0 {
			ipaddr = append(ipaddr, result.A...)
		} else {
			for _, h := range result.HTTPS {
				if len(h.IPv4Hint) > 0 {
					ipaddr = append(ipaddr, h.IPv4Hint.String())
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
					ipaddr = append(ipaddr, h.IPv6Hint.String())
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
	var errs []error
	for _, addr := range ipaddr {
	retry:
		ctx := ctx
		cancel := context.CancelFunc(nil)
		if len(ipaddr) > 1 {
			ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		}
		conn, err := quic.DialAddr(ctx, net.JoinHostPort(addr, port), tc, qc)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			var echErr *tls.ECHRejectionError
			if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
				tc.EncryptedClientHelloConfigList = echErr.RetryConfigList
				goto retry
			}
			errs = append(errs, err)
			continue
		}
		return conn, nil
	}
	return nil, errors.Join(errs...)
}
