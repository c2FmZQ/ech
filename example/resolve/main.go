package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/c2FmZQ/ech"
)

func main() {
	resolver := flag.String("resolver", "cloudflare", "Either cloudflare or google")
	flag.Parse()

	var r *ech.Resolver
	switch *resolver {
	case "google":
		r = ech.GoogleResolver()
	case "cloudflare":
		r = ech.CloudflareResolver()
	default:
		fmt.Fprintln(os.Stderr, "unexpected --resolver value")
		os.Exit(1)
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
