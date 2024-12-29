// Package ech implements a library to support Encrypted Client Hello with a Split
// Mode Topology, as described in https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
//
//	Client ----> Client-Facing Server ----> Backend Servers
//	             (public.example.com)       (private1.example.com)
//	                                        (private2.example.com)
//
// A [ech.Conn] handles the Client-Facing Server part. It transparently inspects
// the TLS handshake and decrypts/decodes Encrypted Client Hello messages. The
// decoded ServerName and/or ALPN protocols can then be used to route the TLS
// connection to the correct backend server.
//
// A regular [tls.Server] Conn with EncryptedClientHelloKeys set in its
// [tls.Config] is required to handle the ECH Config PublicName. The other backend
// servers don't need the ECH keys.
//
//	ln, err := net.Listen("tcp", ":8443")
//	if err != nil {
//	        // ...
//	}
//	defer ln.Close()
//	for {
//	        serverConn, err := ln.Accept()
//	        if err != nil {
//	                // ...
//	        }
//	        go func() {
//	                ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	                defer cancel()
//	                conn, err := ech.NewConn(ctx, serverConn, ech.WithKeys(echKeys))
//	                if err != nil {
//	                        // ...
//	                        return
//	                }
//	                log.Printf("ServerName: %s", conn.ServerName())
//	                log.Printf("ALPNProtos: %s", conn.ALPNProtos())
//
//	                switch host := conn.ServerName(); host {
//	                case "public.example.com":
//	                        server := tls.Server(conn, &tls.Config{
//	                                Certificates:             []tls.Certificate{tlsCert},
//	                                EncryptedClientHelloKeys: echKeys,
//	                        })
//	                        fmt.Fprintf(server, "Hello, this is public.example.com\n")
//	                        server.Close()
//	                default:
//	                        server := tls.Server(conn, &tls.Config{
//	                                Certificates: []tls.Certificate{tlsCert},
//	                        })
//	                        fmt.Fprintf(server, "Hello, this is %s\n", host)
//	                        server.Close()
//	                }
//	        }()
//	}
//
// ECH Configs and ECH ConfigLists are created with [ech.NewConfig] and [ech.ConfigList].
//
// The example directory has working client and server examples.
package ech
