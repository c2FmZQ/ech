package main

import (
	"context"
	"fmt"
	"os"

	"github.com/c2FmZQ/ech"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: resolve <name>")
		os.Exit(1)
	}
	result, err := ech.Resolve(context.Background(), os.Args[1])
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
