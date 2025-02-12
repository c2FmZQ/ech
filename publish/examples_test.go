package publish_test

import (
	"context"
	"log"

	"github.com/c2FmZQ/ech"
	"github.com/c2FmZQ/ech/publish"
)

func Example() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privKey, config, err := ech.NewConfig(1, []byte("www.example.com"))
	if err != nil {
		log.Fatalf("NewConfig: %v", err)
	}
	// Use privKey with ech.Conn or tls.Server
	_ = privKey

	configList, err := ech.ConfigList([]ech.Config{config})
	if err != nil {
		log.Fatalf("ConfigList: %v", err)
	}

	// The API token must have the DNS:Read and DNS:Edit permissions on
	// example.com
	apiToken := "..."
	pub := publish.NewCloudflarePublisher(apiToken)

	records := []publish.Target{
		{Zone: "example.com", Name: "private.example.com"},
	}
	results := pub.PublishECH(ctx, records, configList)
	for i, result := range results {
		log.Printf("[%s] %s: %s", records[i].Zone, records[i].Name, result)
	}
}
