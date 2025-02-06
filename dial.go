package ech

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Dial connects to the given network and address using [net.Dialer] and
// [tls.Client]. Name resolution is done with [DefaultResolver] and
// EncryptedClientHelloConfigList will be set automatically if the hostname has
// a HTTPS DNS record with ech.
func Dial(ctx context.Context, network, addr string, tc *tls.Config) (*tls.Conn, error) {
	return NewDialer().Dial(ctx, network, addr, tc)
}

// NewDialer returns a [tls.Conn] Dialer.
func NewDialer() *Dialer[*tls.Conn] {
	return &Dialer[*tls.Conn]{DialFunc: dialTLSConn}
}

// Dialer contains options for connecting to an address using Encrypted Client
// Hello. It retrieves the ECH config list automatically from DNS HTTP records,
// or from the remote server itself.
type Dialer[T any] struct {
	// RequireECH indicates that Encrypted Client Hello must be available
	// and successfully negotiated for [Dialer.Dial] to return successfully.
	RequireECH bool
	// Resolver specifies the resolver to use for DNS lookups. If nil,
	// [DefaultResolver] is used.
	Resolver *Resolver
	// PublicName is used to fetch the ECH config list from the server when
	// the config list isn't specified in the [tls.Config] or in DNS. In
	// that case, [Dialer.Dial] generates a fake (but valid) config list
	// with this PublicName and use it to establish a TLS connection with
	// the server, which should return the current config list in
	// RetryConfigList.
	PublicName string
	// MaxConcurrency specifies the maximum number of connections that can
	// be attempted in parallel by Dial() when the network address resolves
	// to multiple targets. The default value is 3.
	MaxConcurrency int
	// ConcurrencyInterval is the amount of time to wait before initiating a
	// concurrent connection attempt. The default is 1s.
	ConcurrencyInterval time.Duration
	// Timeout is the amount of time to wait for a single connection to be
	// established, i.e. a call to DialFunc. The default value is 30s.
	Timeout time.Duration
	// DialFunc must be set to a function that will be used to connect to
	// a network address. [NewDialer] automatically sets this value.
	DialFunc func(ctx context.Context, network, addr string, tc *tls.Config) (T, error)
}

// Dial connects to the given network and address using [net.Dialer] and
// [tls.Client]. EncryptedClientHelloConfigList will be set automatically if the
// hostname has a HTTPS DNS record with ech.
func (d *Dialer[T]) Dial(ctx context.Context, network, addr string, tc *tls.Config) (T, error) {
	var nilConn T
	if tc == nil {
		tc = &tls.Config{}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "443"
	}
	resolver := d.Resolver
	if resolver == nil {
		resolver = DefaultResolver
	}
	result, err := resolver.Resolve(ctx, host)
	if err != nil {
		return nilConn, err
	}
	iport, err := strconv.Atoi(port)
	if err != nil {
		return nilConn, err
	}
	if tc.ServerName == "" {
		tc.ServerName = host
	}
	targetChan := make(chan Target)
	connChan := make(chan T)
	errChan := make(chan error)
	doneChan := make(chan struct{})
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sendErr := func(err error) {
		select {
		case <-ctx.Done():
		case errChan <- err:
		}
	}
	sendConn := func(conn T) {
		select {
		case <-ctx.Done():
			if c, ok := any(conn).(io.Closer); ok {
				c.Close()
			}
		case connChan <- conn:
		}
	}

	needECH := tc.EncryptedClientHelloConfigList == nil
	if needECH && d.PublicName != "" {
		id := make([]byte, 1)
		if _, err := io.ReadFull(rand.Reader, id); err != nil {
			return nilConn, err
		}
		_, config, err := NewConfig(id[0], []byte(d.PublicName))
		if err != nil {
			return nilConn, err
		}
		configList, err := ConfigList([]Config{config})
		if err != nil {
			return nilConn, err
		}
		tc.EncryptedClientHelloConfigList = configList
	}

	numWorkers := d.MaxConcurrency
	if numWorkers <= 0 {
		numWorkers = 3
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	interval := d.ConcurrencyInterval
	if interval <= 0 {
		interval = time.Second
	}

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetChan {
				tc := tc.Clone()
				if needECH {
					tc.EncryptedClientHelloConfigList = target.ECH
				}
				if d.RequireECH && tc.EncryptedClientHelloConfigList == nil {
					sendErr(errors.New("unable to get ECH config list"))
					continue
				}
				ctx, cancel := context.WithTimeout(ctx, timeout)
				conn, err := d.DialFunc(ctx, network, target.Address.String(), tc)
				cancel()
				if err != nil {
					sendErr(err)
					continue
				}
				sendConn(conn)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(doneChan)
	}()

	go func() {
		first := true
		for target := range result.Targets(network, iport) {
			if !first {
				select {
				case <-ctx.Done():
					break
				case <-time.After(interval):
				}
			}
			first = false
			targetChan <- target
		}
		close(targetChan)
	}()

	var errs []error
	for {
		select {
		case <-ctx.Done():
			return nilConn, ctx.Err()
		case <-doneChan:
			if len(errs) == 0 {
				return nilConn, errors.New("no address")
			}
			return nilConn, errors.Join(errs...)
		case err := <-errChan:
			errs = append(errs, err)
		case conn := <-connChan:
			return conn, nil
		}
	}
}

func dialTLSConn(ctx context.Context, network, addr string, tc *tls.Config) (*tls.Conn, error) {
	netDialer := &net.Dialer{
		Resolver: &net.Resolver{
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("not using go resolver")
			},
		},
	}

	var retried bool
retry:
	conn, err := netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, tc)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		var echErr *tls.ECHRejectionError
		if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 && !retried {
			tc.EncryptedClientHelloConfigList = echErr.RetryConfigList
			retried = true
			goto retry
		}
		return nil, err
	}
	return tlsConn, nil
}
