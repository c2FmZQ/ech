[![Go Reference](https://pkg.go.dev/badge/github.com/c2FmZQ/ech.svg)](https://pkg.go.dev/github.com/c2FmZQ/ech)

# Encrypted Client Hello with Split Mode Topology

This repo implements a go library to support Encrypted Client Hello with a Split Mode Topology, as described in https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni/

```mermaid
flowchart LR
  subgraph Client
    c1("Client")
  end
  subgraph Client-Facing Server
    prx((("public.example.com")))
  end
  subgraph Backend Servers
    be1("private1.example.com")
    be2("private2.example.com")
  end
  c1-->prx
  prx-->be1
  prx-->be2
```

The ECH library handles the Client-Facing Server part. A `ech.Conn` transparently inspects the TLS handshake and decrypts/decodes Encrypted Client Hello messages. The decoded ServerName and/or ALPN protocols can then be used to route the TLS connection to the right backend server.

The [example](https://github.com/c2FmZQ/ech/tree/main/example) directory has working client and server examples.

See the [godoc](https://pkg.go.dev/github.com/c2FmZQ/ech) for more details.
