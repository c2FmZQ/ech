package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/hashicorp/go-retryablehttp"
)

var dohClient = func() *retryablehttp.Client {
	c := retryablehttp.NewClient()
	c.Logger = nil
	return c
}()

// DoH sends a RFC 8484 DoH (DNS-over-HTTPS) request to URL.
func DoH(ctx context.Context, msg *Message, URL string) (*Message, error) {
	raw := msg.Bytes()
	if len(raw) == 0 {
		return nil, ErrDecodeError
	}
	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", URL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-message")
	req.Header.Set("content-type", "application/dns-message")
	req.Header.Set("user-agent", "")
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}
	if cl := resp.Header.Get("content-length"); cl != "" {
		sz, err := strconv.Atoi(cl)
		if err != nil || sz < 0 || sz > 65535 {
			return nil, ErrDecodeError
		}
		body := make([]byte, sz)
		if _, err := io.ReadFull(io.LimitReader(resp.Body, 65536), body); err != nil {
			return nil, err
		}
		return DecodeMessage(body)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	if len(body) > 65535 {
		return nil, ErrDecodeError
	}
	return DecodeMessage(body)
}
