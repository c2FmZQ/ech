package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/c2FmZQ/ech/dns"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <url> <name> <type>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	url := os.Args[1]
	name := os.Args[2]
	typ := os.Args[3]

	iType := dns.RRType(typ)
	if iType == 0 {
		v, err := strconv.Atoi(typ)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%q: %v\n", typ, err)
			os.Exit(1)
		}
		iType = uint16(v)
	}
	qq := &dns.Message{
		RD: 1,
		Question: []dns.Question{{
			Name:  name,
			Type:  iType,
			Class: 1,
		}},
	}
	result, err := dns.DoH(context.Background(), qq, url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns.DoH: %v", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(result)
}
