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

// Dial connects to the given network and address. Name resolution is done with
// [DefaultResolver]. It uses HTTPS DNS records to retrieve the server's
// Encrypted Client Hello (ECH) Config List and uses it automatically if found.
//
// If the name resolution returns multiple IP addresses, Dial iterates over them
// until a connection is successfully established.
//
// Dial is equivalent to:
//
//	NewDialer().Dial(...)
//
// For finer control, instantiate a [Dialer] first.  Then, call Dial:
//
//	dialer := NewDialer()
//	dialer.RequireECH = true
//	conn, err := dialer.Dial(...)
func Dial(ctx context.Context, network, addr string, tc *tls.Config) (*tls.Conn, error) {
	return NewDialer().Dial(ctx, network, addr, tc)
}

// NewDialer returns a [tls.Conn] Dialer.
func NewDialer() *Dialer[*tls.Conn] {
	return &Dialer[*tls.Conn]{
		DialFunc: func(ctx context.Context, network, addr string, tc *tls.Config) (*tls.Conn, error) {
			tlsDialer := &tls.Dialer{
				NetDialer: &net.Dialer{
					Resolver: &net.Resolver{
						Dial: func(context.Context, string, string) (net.Conn, error) {
							return nil, errors.New("not using go resolver")
						},
					},
				},
				Config: tc,
			}
			conn, err := tlsDialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return conn.(*tls.Conn), nil
		},
	}
}

// Dialer contains options for connecting to an address using Encrypted Client
// Hello. It retrieves the Encrypted Client Hello (ECH) Config List
// automatically from DNS, or from the remote server itself.
//
// Dialer uses RFC 8484 DNS-over-HTTPS (DoH) and RFC 9460 HTTPS Resource Records, along
// with traditional A, AAAA, CNAME records for name resolution. If a HTTPS record
// contains an ECH config list, it can be used automatically. [Dialer.Dial] also supports
// concurrent connection attempts to gracefully handle slow or unreachable addresses.
type Dialer[T any] struct {
	// RequireECH indicates that Encrypted Client Hello must be available
	// and successfully negotiated for Dial to return successfully.
	// By default, when RequireECH is false, Dial falls back to regular
	// plaintext Client Hello when a Config List isn't found.
	RequireECH bool
	// Resolver specifies the resolver to use for DNS lookups. If nil,
	// DefaultResolver is used.
	Resolver *Resolver
	// PublicName is used to fetch the ECH Config List from the server when
	// the Config List isn't specified in the tls.Config or in DNS. In
	// that case, Dial generates a fake (but valid) Config List with this
	// PublicName and use it to establish a TLS connection with the server,
	// which should return the real Config List in RetryConfigList.
	PublicName string
	// MaxConcurrency specifies the maximum number of connections that can
	// be attempted in parallel by Dial when the network address resolves to
	// multiple targets. The default value is 3.
	MaxConcurrency int
	// ConcurrencyDelay is the amount of time to wait before initiating a
	// new concurrent connection attempt. The default is 1s.
	ConcurrencyDelay time.Duration
	// Timeout is the amount of time to wait for a single connection to be
	// established. The default value is 30s.
	Timeout time.Duration
	// DialFunc must be set to a function that will be used to connect to
	// a network address. NewDialer automatically sets this value.
	DialFunc func(ctx context.Context, network, addr string, tc *tls.Config) (T, error)
}

// Dial connects to the given network and address. It uses HTTPS DNS records to
// retrieve the server's Encrypted Client Hello (ECH) Config List and uses it
// automatically if found.
//
// If the name resolution returns multiple IP addresses, Dial iterates over them
// until a connection is successfully established. See [Dialer] for finer control.
func (d *Dialer[T]) Dial(ctx context.Context, network, addr string, tc *tls.Config) (T, error) {
	var nilConn T
	if d.DialFunc == nil {
		return nilConn, errors.New("DialFunc must be set")
	}
	if tc == nil {
		tc = &tls.Config{}
	} else {
		tc = tc.Clone()
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
	wakeChan := make(chan struct{})
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
	wake := func() {
		select {
		case wakeChan <- struct{}{}:
		default:
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
	delay := d.ConcurrencyDelay
	if delay <= 0 {
		delay = time.Second
	}

	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetChan {
				tc := tc.Clone()
				if needECH && target.ECH != nil {
					tc.EncryptedClientHelloConfigList = target.ECH
				}
				if d.RequireECH && tc.EncryptedClientHelloConfigList == nil {
					sendErr(errors.New("unable to get ECH config list"))
					continue
				}
				ctx, cancel := context.WithTimeout(ctx, timeout)
				conn, err := d.dialOne(ctx, network, target.Address.String(), tc)
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
		close(errChan)
	}()

	go func() {
		first := true
		for target := range result.Targets(network, iport) {
			if !first {
				select {
				case <-ctx.Done():
					break
				case <-wakeChan:
				case <-time.After(delay):
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
		case conn := <-connChan:
			return conn, nil
		case err, ok := <-errChan:
			if !ok {
				if len(errs) == 0 {
					return nilConn, errors.New("no address")
				}
				return nilConn, errors.Join(errs...)
			}
			errs = append(errs, err)
			wake()
		}
	}
}

func (d *Dialer[T]) dialOne(ctx context.Context, network, addr string, tc *tls.Config) (T, error) {
	var nilConn T
	var retried bool
retry:
	conn, err := d.DialFunc(ctx, network, addr, tc)
	if err != nil {
		var echErr *tls.ECHRejectionError
		if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 && !retried {
			tc.EncryptedClientHelloConfigList = echErr.RetryConfigList
			retried = true
			goto retry
		}
		return nilConn, err
	}
	return conn, nil
}
