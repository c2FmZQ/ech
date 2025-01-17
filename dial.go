package ech

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"time"
)

// Dial connects to the given network and address using [net.Dialer] and
// [tls.Client]. Name resolution is done with [Resolver] and
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
	iport, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	targets := result.Targets(network, iport)
	if len(targets) == 0 {
		return nil, errors.New("no address")
	}
	if tc.ServerName == "" {
		tc.ServerName = host
	}
	needECH := tc.EncryptedClientHelloConfigList == nil
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("cannot use go resolver")
			},
		},
	}
	var errs []error
	for _, target := range targets {
	retry:
		ctx := ctx
		if len(targets) > 1 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
		}
		conn, err := dialer.DialContext(ctx, network, target.Address.String())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if needECH {
			tc.EncryptedClientHelloConfigList = target.ECH
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
