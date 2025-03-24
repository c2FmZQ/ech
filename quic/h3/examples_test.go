package h3

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/quic-go/quic-go"
)

func ExampleNewTransport() {
	url := "https://private.example.com"

	transport := NewTransport(&quic.Config{})
	transport.Dialer.RequireECH = true
	transport.TLSConfig = &tls.Config{
		NextProtos: []string{
			"h3",
		},
	}

	client := &http.Client{Transport: transport}

	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("%q: %v", url, err)
	}
	defer resp.Body.Close()
	fmt.Printf("==== %s Status:%d ====\n", url, resp.StatusCode)
	io.Copy(os.Stdout, resp.Body)
}
