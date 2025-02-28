// This is an example of an HTTP client using [ech.Transport] to send an HTTP
// request using Encrypted Client Hello (ECH).
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/c2FmZQ/ech"
)

func main() {
	requireECH := flag.Bool("require-ech", false, "Require Encrypted Client Hello.")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-require-ech] <url> ...\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	transport := ech.NewTransport()
	transport.Dialer.RequireECH = *requireECH

	client := &http.Client{Transport: transport}

	for _, url := range flag.Args() {
		resp, err := client.Get(url)
		if err != nil {
			log.Fatalf("%q: %v", url, err)
		}
		fmt.Printf("==== %s Status:%d ====\n", url, resp.StatusCode)
		io.Copy(os.Stdout, resp.Body)
		resp.Body.Close()
	}
}
