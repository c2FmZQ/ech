package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/c2FmZQ/ech"
	"github.com/quic-go/quic-go"
)

// Dial connects to the given network and address using [quic.DialAddr]. Name
// resolution is done with [ech.Resolver] and EncryptedClientHelloConfigList will
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
	iport, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	targets := result.Targets(network, iport)
	if len(targets) == 0 {
		return nil, errors.New("no address")
	}
	if len(targets) == 0 {
		return nil, errors.New("no address")
	}
	if tc.ServerName == "" {
		tc.ServerName = host
	}
	needECH := tc.EncryptedClientHelloConfigList == nil
	var errs []error
	for _, target := range targets {
		retried := false
	retry:
		ctx := ctx
		cancel := context.CancelFunc(nil)
		if len(targets) > 1 {
			ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		}
		if needECH && !retried {
			tc.EncryptedClientHelloConfigList = target.ECH
		}
		conn, err := quic.DialAddr(ctx, target.Address.String(), tc, qc)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			var echErr *tls.ECHRejectionError
			if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 && !retried {
				tc.EncryptedClientHelloConfigList = echErr.RetryConfigList
				retried = true
				goto retry
			}
			errs = append(errs, err)
			continue
		}
		return conn, nil
	}
	return nil, errors.Join(errs...)
}
