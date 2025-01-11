package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/c2FmZQ/ech"
)

func main() {
	resolver := flag.String("resolver", "cloudflare", "One of cloudflare, google, wikimedia")
	flag.Parse()

	var r *ech.Resolver
	switch *resolver {
	case "cloudflare":
		r = ech.CloudflareResolver()
	case "google":
		r = ech.GoogleResolver()
	case "wikimedia":
		r = ech.WikimediaResolver()
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
	for _, a := range result.A {
		fmt.Printf("    A: %s\n", a)
	}
	for _, aaaa := range result.AAAA {
		fmt.Printf(" AAAA: %s\n", aaaa)
	}
	for _, h := range result.HTTPS {
		fmt.Printf("HTTPS: %s\n", h)
	}
}
