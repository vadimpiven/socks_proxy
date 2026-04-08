# socks5-srv

Lightweight, embeddable SOCKS5 proxy server in Go implementing:

- [RFC 1928](rfcs/rfc1928.txt) — SOCKS5 protocol
- [RFC 1929](rfcs/rfc1929.txt) — username/password authentication

| Feature           | Detail                                                |
| ----------------- | ----------------------------------------------------- |
| Commands          | `CONNECT` (TCP), `UDP ASSOCIATE` (datagram relay)     |
| Auth              | No-auth (0x00), username/password (0x02)              |
| Addresses         | IPv4, IPv6, domain names                              |
| Per-user policy   | Private-destination access controlled per user        |
| Concurrency       | Configurable max connections (default 1024)           |
| Graceful shutdown | Drains active sessions before exit                    |
| Hot reload        | SIGHUP reloads config; active sessions stay open      |
| Platforms         | Linux, macOS, Windows (hot reload is Unix-only)       |

Out of scope (will not be implemented):

- BIND command (0x02)
- GSSAPI authentication (0x01)
- UDP fragmentation (dropped per RFC 1928 section 7)

## Build

Requires Go 1.26+.

```sh
go build -o socks5-srv .
```

## CLI

```text
socks5-srv [flags]
  -config string   path to TOML config (default "socks5-srv.toml")
  -verbose         enable verbose log output
  -version         print version and exit
```

On first run the server writes a default config to disk. Password
authentication is enabled with an empty user list, so all connections
are denied until the operator adds at least one user and reloads
(`kill -HUP <pid>`).

### Config file (TOML)

```toml
addr = ":1080"
# bind = "eth0"   # outbound interface (default: OS routing)

[users]
# Key is an admin label (never sent over the wire).
# "login" defaults to key if omitted.

# Explicit login (e.g. a random token):
alice = { login = "xK9mW2pQ", password = "s3cr3t", allow_private = true }
# Login omitted — client authenticates as "bob":
bob   = { password = "hunter2" }

# Remove [users] entirely for no-auth mode.
```

| Field           | Scope    | Description                                      |
| --------------- | -------- | ------------------------------------------------ |
| `addr`          | global   | Listen address (default `":1080"`)               |
| `bind`          | global   | Outbound network interface (default: OS routing) |
| `login`         | per-user | SOCKS5 username (defaults to key)                |
| `password`      | per-user | SOCKS5 password (required, RFC 1929)             |
| `allow_private` | per-user | Permit CONNECT to private/loopback destinations  |

## Library

The `socks5` package has zero transitive dependencies (stdlib only).
It exposes `socks5.User` with TOML struct tags so CLI and Go code
share the same field names.

`NewServer` requires an explicit auth mode: `Users` or
`Authenticator`. A zero-value config is rejected.

### Username/password authentication

```go
ctx, stop := signal.NotifyContext(context.Background(),
    syscall.SIGINT, syscall.SIGTERM)
defer stop()

srv, err := socks5.NewServer(socks5.Config{
    Users: map[string]socks5.User{
        // Explicit login — client sends "xK9mW2pQ":
        "alice": {Login: "xK9mW2pQ", Password: "s3cr3t", AllowPrivate: true},
        // Login omitted — defaults to "bob":
        "bob": {Password: "hunter2"},
    },
    // Dial: myDialer.DialContext,      // proxy chaining, TLS, metrics
    // BindAddr: "203.0.113.1",         // pin outbound IP (mutex with Dial)
    // TrustedIPs: []netip.Addr{...},   // bypass auth for these clients
})
if err != nil {
    log.Fatal(err)
}
log.Fatal(srv.ListenAndServe(ctx, ":1080"))
```

Per-user `AllowPrivate` controls CONNECT to private/loopback IPs.
Trusted-IP bypass always permits private destinations.

### No authentication

```go
srv, err := socks5.NewServer(socks5.Config{
    Authenticator: socks5.NoAuthAuthenticator{},
})
```

All private destinations are permitted. Use `Users` for granular
per-user control.

### Custom credential backend (LDAP, database)

Implement `socks5.CredentialStore` (one method: `Valid(user, pass)
bool`):

```go
srv, err := socks5.NewServer(socks5.Config{
    Authenticator: socks5.UserPassAuthenticator{Credentials: myStore},
})
```

## Testing

```sh
go test ./...
go test -race ./...
```

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE.txt) or [MIT](LICENSE-MIT.txt).
