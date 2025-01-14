package main

import (
	"context"
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
			fmt.Fprintf(os.Stderr, "%q: %v", typ, err)
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
	for i, v := range result.Question {
		fmt.Printf("  Question[%d] Name: %q Type: %d Class: %d\n", i, v.Name, v.Type, v.Class)
	}
	for i, v := range result.Answer {
		fmt.Printf("    Answer[%d] Name: %q Type: %d Class: %d Data: %+v\n", i, v.Name, v.Type, v.Class, v.Data)
	}
	for i, v := range result.Authority {
		fmt.Printf(" Authority[%d] Name: %q Type: %d Class: %d Data: %+v\n", i, v.Name, v.Type, v.Class, v.Data)
	}
	for i, v := range result.Additional {
		fmt.Printf("Additional[%d] Name: %q Type: %d Class: %d Data: %+v\n", i, v.Name, v.Type, v.Class, v.Data)
	}
}
