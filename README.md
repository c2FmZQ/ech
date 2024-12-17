# Encrypted Client Hello with Split Mode Topology

This repo implements a go library to support Encrypted Client Hello with a Split Mode Topology.

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

The ECH library handles the Client-Facing Server part.

