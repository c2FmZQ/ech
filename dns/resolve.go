package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// DoH sends a RFC 8484 DoH (DNS-over-HTTPS) request to URL.
func DoH(ctx context.Context, msg *Message, URL string) (*Message, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", URL, bytes.NewReader(msg.Bytes()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/dns-message")
	req.Header.Set("content-type", "application/dns-message")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}
	sz, err := strconv.Atoi(resp.Header.Get("content-length"))
	if err != nil || sz < 0 || sz > 65535 {
		return nil, ErrDecodeError
	}
	body := make([]byte, sz)
	if _, err := io.ReadFull(resp.Body, body); err != nil {
		return nil, err
	}
	return DecodeMessage(body)
}