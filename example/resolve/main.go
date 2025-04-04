// This is an example showing how to use [ech.Resolve] to securely and privately
// find the Encrypted Client Hello (ECH) Config List for a DNS name.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/c2FmZQ/ech"
)

func main() {
	resolver := flag.String("resolver", "cloudflare", "One of cloudflare, google, wikimedia, insecure")
	flag.Parse()

	var r *ech.Resolver
	switch *resolver {
	case "cloudflare":
		r = ech.CloudflareResolver()
	case "google":
		r = ech.GoogleResolver()
	case "wikimedia":
		r = ech.WikimediaResolver()
	case "insecure":
		r = ech.InsecureGoResolver()
	default:
		var err error
		if r, err = ech.NewResolver(*resolver); err != nil {
			fmt.Fprintf(os.Stderr, "--resolver: %v\n", err)
			os.Exit(1)
		}
	}

	if len(flag.Args()) != 1 {
		fmt.Fprintln(os.Stderr, "usage: resolve <name>")
		os.Exit(1)
	}
	result, err := r.Resolve(context.Background(), flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Resolve: %v\n", err)
		os.Exit(1)
	}
	for _, a := range result.Address {
		fmt.Printf(" Addr: %s\n", a)
	}
	for _, h := range result.HTTPS {
		fmt.Printf("HTTPS: %s\n", h)
	}
	first := true
	for a := range result.Targets("tcp") {
		if first {
			first = false
			fmt.Println("\nOrdered Targets:")
		}
		var ech string
		if len(a.ECH) > 0 {
			ech = " ech=" + base64.StdEncoding.EncodeToString(a.ECH)
		}
		var alpn string
		if len(a.ALPN) > 0 {
			alpn = " alpn=" + strings.Join(a.ALPN, ",")
		}
		fmt.Printf("  %s%s%s\n", a.Address, alpn, ech)
	}
}
