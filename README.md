# socks5-srv

Lightweight, embeddable SOCKS5 proxy server in Go implementing:

- [RFC 1928](rfcs/rfc1928.txt) — SOCKS5 protocol
- [RFC 1929](rfcs/rfc1929.txt) — username/password authentication

| Feature    | Detail                                                            |
| ---------- | ----------------------------------------------------------------- |
| Protocols  | TCP tunneling, UDP relay                                          |
| Auth       | None, or username/password                                        |
| Addresses  | IPv4, IPv6, domain names                                          |
| Platforms  | Linux, macOS, Windows (signals are Unix-only)                     |
| Operations | Per-user access control, hot config reload, zero-downtime upgrade |

## CLI

```sh
go install github.com/vadimpiven/socks5-srv/cmd/socks5-srv@latest
```

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

```go
srv, err := socks5.NewServer(socks5.Config{
    Authenticator: socks5.UserPassAuthenticator{Credentials: myStore},
})
```

Implement `socks5.CredentialStore` (one method: `Valid(user, pass)
bool`).

## Production

### Zero-downtime upgrade

```sh
mv socks5-srv-new socks5-srv   # replace binary (atomic on same fs)
kill -USR2 $(pgrep socks5-srv) # trigger graceful upgrade
```

The old process re-executes the on-disk binary, passing the listening
socket via fd inheritance. The new process accepts immediately; the old
one drains active sessions and exits. If the new binary fails to start,
the old process keeps serving.

### systemd

```ini
[Unit]
Description=SOCKS5 proxy server
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/bin/socks5-srv -config /etc/socks5-srv/socks5-srv.toml
ExecReload=kill -HUP $MAINPID
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

- **Config reload** (zero downtime): `systemctl reload socks5-srv`
- **Binary upgrade** (zero downtime):

```sh
mv socks5-srv-new /usr/local/bin/socks5-srv
systemctl kill -s USR2 socks5-srv
```

The new process notifies systemd of its PID via the sd_notify
protocol (`MAINPID=<pid>`), so `systemctl status` and
`systemctl stop` continue to work correctly after an upgrade.

## Development

Requires Go 1.26+.

```sh
go build -o socks5-srv ./cmd/socks5-srv
go test ./...
go test -race ./...
```

## Scope

Not implemented by design:

- BIND command (0x02)
- GSSAPI authentication (0x01)
- UDP fragmentation (dropped per RFC 1928 section 7)

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE.txt) or [MIT](LICENSE-MIT.txt).
