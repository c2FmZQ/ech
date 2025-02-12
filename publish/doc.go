// Package publish is used to publish Encrypted Client Hello (ECH) Config Lists
// to DNS HTTPS records (RFC 9460).
//
//	import (
//		"log"
//
//		"github.com/c2FmZQ/ech"
//		"github.com/c2FmZQ/ech/publish"
//	)
//
//	func main() {
//		privKey, config, err := ech.NewConfig(1, []byte("www.example.com"))
//		if err != nil {
//			log.Fatalf("NewConfig: %v", err)
//		}
//		configList, err := ech.ConfigList([]ech.Config{config})
//		if err != nil {
//			log.Fatalf("ConfigList: %v", err)
//		}
//
//		apiToken := "..."
//		pub := publish.NewCloudflarePublisher(apiToken)
//
//		records := []publish.Target{
//			{Zone: "example.com", Name: "private.example.com"},
//		}
//		results := pub.PublishECH(ctx, records, configList)
//		for i, result := range results {
//			log.Printf("[%s] %s: %s", records[i].Zone, records[i].Name, result)
//		}
//	}
package publish
