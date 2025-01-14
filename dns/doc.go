// Package dns implements low-level DNS message encoding and decoding to
// interface with RFC 8484 "DNS Queries over HTTPS" (DoH) services.
//
// Example:
//
//	qq := &dns.Message{
//		RD: 1,
//		Question: []dns.Question{{
//			Name:  "www.google.com",
//			Type:  1,
//			Class: 1,
//		}},
//	}
//	result, err := dns.DoH(context.Background(), qq, "https://1.1.1.1/dns-query")
//	if err != nil {
//		fmt.Fprintf(os.Stderr, "dns.DoH: %v", err)
//		os.Exit(1)
//	}
//	enc := json.NewEncoder(os.Stdout)
//	enc.SetIndent("", "  ")
//	enc.Encode(result)
package dns
