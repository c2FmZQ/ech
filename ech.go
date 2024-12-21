// Package ech implements tools to support Encrypted Client Hello with a Split
// Mode Topology.
package ech

import (
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/c2FmZQ/ech/internal/hpke"
)

var _ net.Conn = (*Conn)(nil)

// Option is a argument passed to New.
type Option func(*Conn)

// WithKeys enables the decryption of Encrypted Client Hello messages.
func WithKeys(keys []Key) Option {
	return func(c *Conn) {
		c.keys = append(c.keys, keys...)
	}
}

// WithDebug enables debugging.
func WithDebug(f func(format string, arg ...any)) Option {
	return func(c *Conn) {
		c.debugf = f
	}
}

// New returns a [Conn] that manages Encrypted Client Hello in TLS connections,
// as defined in https://datatracker.ietf.org/doc/draft-ietf-tls-esni/ .
//
// Encrypted Client Hello handshake messages are decrypted and replaced with the
// ClientHelloInner transparently. If decryption fails, the HelloClientOuter is
// used instead.
//
// When New() returns, the first ClientHello message has already been
// processed. Conn continues to inspect the other handshake messages for
// retries. If ClientHello is retried, it will be processed similarly to the
// first one, with some extra restrictions.
//
// The ctx is used while reading the initial ClientHello only. It is not used
// after New returns.
func New(ctx context.Context, conn net.Conn, options ...Option) (outConn *Conn, err error) {
	defer convertErrorsToAlerts(conn, err)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			conn.SetDeadline(time.Now())
		}
	}()
	record, err := readRecord(conn)
	if err != nil {
		return nil, err
	}
	if record[0] != 22 { // TLS Handshake
		return nil, fmt.Errorf("%w: content type %d != 22 (%q)", ErrUnexpectedMessage, record[0], record[:5])
	}
	outConn = &Conn{
		Conn:       conn,
		retryCount: new(atomic.Int32),
	}
	for _, opt := range options {
		opt(outConn)
	}
	if outConn.debugf == nil {
		outConn.debugf = func(string, ...any) {}
	}
	if outConn.outer, outConn.inner, err = outConn.handleClientHello(record); err != nil {
		return outConn, err
	}
	outConn.readPassthrough = outConn.inner == nil
	outConn.writePassthrough = outConn.inner == nil

	if outConn.inner != nil {
		outConn.readBuf, err = outConn.inner.Marshal()
	} else {
		outConn.readBuf, err = outConn.outer.Marshal()
	}
	if err != nil {
		return outConn, err
	}
	return outConn, nil
}

// Conn manages Encrypted Client Hello in TLS connections, as defined in
// https://datatracker.ietf.org/doc/draft-ietf-tls-esni/ .
type Conn struct {
	net.Conn
	outer *clientHello
	inner *clientHello

	hpkeCtx *hpke.Receipient

	keys             []Key
	debugf           func(string, ...any)
	readBuf          []byte
	readErr          error
	writeBuf         []byte
	retryCount       *atomic.Int32
	readPassthrough  bool
	writePassthrough bool
}

// ECHPresented indicates whether the client presented an Encrypted Client
// Hello.
func (c *Conn) ECHPresented() bool {
	return c != nil && c.outer != nil && c.outer.echExt != nil && c.outer.echExt.Type == 0
}

// ECHAccepted indicates whether the client's Encrypted Client Hello was
// successfully decrypted and validated.
func (c *Conn) ECHAccepted() bool {
	return c != nil && c.inner != nil
}

// ServerName returns the SNI value extracted from the ClientHello.
func (c *Conn) ServerName() string {
	if c != nil && c.inner != nil {
		return c.inner.ServerName
	}
	if c != nil && c.outer != nil {
		return c.outer.ServerName
	}
	return ""
}

// ALPNProtos returns the ALPN protocol values extracted from the ClientHello.
func (c *Conn) ALPNProtos() []string {
	if c != nil && c.inner != nil {
		return slices.Clone(c.inner.ALPNProtos)
	}
	if c != nil && c.outer != nil {
		return slices.Clone(c.outer.ALPNProtos)
	}
	return nil
}

func (c *Conn) handleClientHello(record []byte) (outer, inner *clientHello, err error) {
	if outer, err = parseClientHello(record[5:]); err != nil {
		return nil, nil, err
	}
	if outer.hasECHOuterExtensions {
		return nil, nil, fmt.Errorf("%w: ClientHelloOuter has ech_outer_extensions", ErrIllegalParameter)
	}
	if inner, err = c.processEncryptedClientHello(outer); err != nil && err != ErrNoMatch {
		return nil, nil, err
	}
	return outer, inner, nil
}

func (c *Conn) processEncryptedClientHello(h *clientHello) (*clientHello, error) {
	if !h.tls13 || h.echExt == nil || h.echExt.Type != 0 || len(c.keys) == 0 {
		return nil, nil
	}
	var innerBytes []byte
	for _, key := range c.keys {
		echPriv, err := hpke.ParseHPKEPrivateKey(hpke.DHKEM_X25519_HKDF_SHA256, key.PrivateKey)
		if err != nil {
			return nil, err
		}
		if c.hpkeCtx == nil && len(h.echExt.Enc) > 0 {
			info := append([]byte("tls ech\x00"), key.Config...)
			ctx, err := hpke.SetupReceipient(hpke.DHKEM_X25519_HKDF_SHA256, h.echExt.KDF, h.echExt.AEAD, echPriv, info, h.echExt.Enc)
			if err != nil {
				continue
			}
			c.hpkeCtx = ctx
		}
		if c.hpkeCtx == nil {
			return nil, ErrIllegalParameter
		}
		aad, err := h.marshalAAD()
		if err != nil {
			return nil, err
		}
		innerBytes, err = c.hpkeCtx.Open(aad, h.echExt.Payload)
		if err != nil {
			continue
		}
	}
	if innerBytes == nil {
		return nil, ErrNoMatch
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(0x01) // msg_type: ClientHello
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(innerBytes)
	})
	msg, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	inner, err := parseClientHello(msg)
	if err != nil {
		return nil, err
	}
	if inner.echExt == nil || inner.echExt.Type != 1 {
		return nil, fmt.Errorf("%w: encrypted_client_hello missing", ErrIllegalParameter)
	}
	inner.LegacySessionID = h.LegacySessionID

	var eoeSeen bool
	var newExt []extension
	for _, ext := range inner.Extensions {
		if ext.Type != 0xfd00 {
			newExt = append(newExt, ext)
			continue
		}
		if eoeSeen {
			return nil, fmt.Errorf("%w: ech_outer_extensions appears more than once", ErrIllegalParameter)
		}
		eoeSeen = true
		s := cryptobyte.String(ext.Data)
		var want cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&want) {
			return nil, ErrDecodeError
		}
		outerPos := 0
		for !want.Empty() {
			var extType uint16
			if !want.ReadUint16(&extType) {
				return nil, ErrDecodeError
			}
			if extType == 0xfe0d {
				return nil, fmt.Errorf("%w: ech_outer_extensions contains 0x%x", ErrIllegalParameter, extType)
			}
			found := false
			for outerPos < len(h.Extensions) {
				p := outerPos
				outerPos++
				if h.Extensions[p].Type != extType {
					continue
				}
				newExt = append(newExt, h.Extensions[p])
				found = true
				break
			}
			if !found {
				return nil, fmt.Errorf("%w: ech_outer_extensions 0x%x not found", ErrIllegalParameter, extType)
			}
		}
	}
	inner.Extensions = newExt

	// Parse the decoded inner hello again to extract extensions data, e.g. ALPNProtos.
	m, err := inner.Marshal()
	if err != nil {
		return nil, err
	}
	return parseClientHello(m[5:])
}

func (c *Conn) Read(b []byte) (int, error) {
	if !c.readPassthrough && len(c.readBuf) == 0 && c.readErr == nil {
		r, err := readRecord(c.Conn)
		if len(r) >= 5 {
			if r[0] == 22 {
				c.debugf("Read %s(%d) %s\n", contentType(r[0]), r[0], handshakeMessageTypes[r[5]])
			} else {
				c.debugf("Read %s(%d)\n", contentType(r[0]), r[0])
			}
		}
		switch {
		case err != nil:
			c.debugf("Read error %v\n", err)
			c.readErr = err
		case r[0] == 23:
			c.readPassthrough = true
		case r[0] == 22 && r[5] == 1 && c.retryCount.Load() == 1:
			c.debugf("Handshake Retried ClientHello\n")
			_, inner, err := c.handleClientHello(r)
			if err != nil {
				c.readErr = err
				convertErrorsToAlerts(c, err)
				return 0, err
			}
			if inner == nil || c.inner.ServerName != inner.ServerName || !slices.Equal(c.inner.ALPNProtos, inner.ALPNProtos) {
				c.readErr = fmt.Errorf("%w: second client_hello mismatch", ErrIllegalParameter)
				convertErrorsToAlerts(c, c.readErr)
				return 0, c.readErr
			}
			r, c.readErr = inner.Marshal()
		}
		c.readBuf = r
	}
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		if len(c.readBuf) == 0 {
			return n, c.readErr
		}
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.writePassthrough && len(c.writeBuf) == 0 {
		return c.Conn.Write(b)
	}
	c.writeBuf = append(c.writeBuf, b...)
	for len(c.writeBuf) >= 5 {
		length := uint32(c.writeBuf[3])<<8 | uint32(c.writeBuf[4])
		if length > 16384 {
			return 0, fmt.Errorf("%w: record length %d > 16384", ErrDecodeError, length)
		}
		sz := int(length) + 5
		if sz > len(c.writeBuf) {
			break
		}
		if err := c.inspectWrite(c.writeBuf[:sz]); err != nil {
			return 0, err
		}
		n, err := c.Conn.Write(c.writeBuf[:sz])
		c.writeBuf = c.writeBuf[n:]
		if err != nil {
			return min(len(b), n), err
		}
		if n != sz {
			return min(len(b), n), io.ErrShortWrite
		}
	}
	return len(b), nil
}

func (c *Conn) inspectWrite(record []byte) error {
	recType := c.writeBuf[0]
	msgType := c.writeBuf[5]
	if recType == 22 {
		c.debugf("Write %s(%d) %s\n", contentType(recType), recType, handshakeMessageTypes[msgType])
	} else {
		c.debugf("Write %s(%d)\n", contentType(recType), recType)
	}
	switch {
	case recType == 23:
		c.writePassthrough = true
	case recType == 22 && msgType == 2: // Handshake / ServerHello
		h, err := parseServerHello(c.writeBuf[5:])
		if err != nil {
			return fmt.Errorf("%w: parseServerHello: %v\n", ErrDecodeError, err)
		}
		if h.IsHelloRetryRequest() {
			c.debugf("HelloRetryRequest: %s\n", h)
			c.retryCount.Add(1)
		}
	}
	return nil
}
