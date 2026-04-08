// SPDX-License-Identifier: Apache-2.0 OR MIT

// Command socks5-srv starts a lightweight SOCKS5 proxy server.
//
// It supports TCP CONNECT and UDP ASSOCIATE through IPv4 and IPv6 networks,
// with optional username/password authentication per RFC 1928 and RFC 1929.
//
// By default private, loopback, and link-local destinations are blocked
// (see [socks5.DenyPrivateDestinations]). Use -private for deployments that
// intentionally proxy to internal infrastructure.
//
// Usage:
//
//	socks5-srv [flags]
//	  -addr      :1080         listen address (host:port)
//	  -user      name          require username/password authentication
//	  -pass      secret        password (must pair with -user)
//	  -bind      203.0.113.1   bind outgoing connections to this IP
//	  -allow     127.0.0.1,::1 IPs that bypass auth (comma-separated)
//	  -private                 allow connections to private/loopback destinations
//	  -quiet                   suppress informational log output
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/vadimpiven/socks5-srv/socks5"
)

func main() {
	addr := flag.String("addr", ":1080", "listen address (host:port)")
	user := flag.String("user", "", "username for client authentication")
	pass := flag.String("pass", "", "password for client authentication")
	bind := flag.String("bind", "", "local IP for outbound connections")
	allow := flag.String("allow", "", "comma-separated IPs allowed without authentication")
	private := flag.Bool("private", false, "allow connections to private/loopback IP destinations")
	quiet := flag.Bool("quiet", false, "suppress informational log output")
	flag.Parse()

	if (*user == "") != (*pass == "") {
		fmt.Fprintln(os.Stderr, "error: -user and -pass must be provided together")
		os.Exit(1)
	}
	if *allow != "" && *user == "" {
		fmt.Fprintln(os.Stderr, "error: -allow requires -user/-pass")
		os.Exit(1)
	}

	logLevel := slog.LevelInfo
	if *quiet {
		logLevel = slog.LevelWarn
	}

	cfg := socks5.Config{
		Logger:                   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})),
		BindAddr:                 *bind,
		AllowPrivateDestinations: *private,
	}

	if *user != "" {
		cfg.Authenticators = []socks5.Authenticator{
			socks5.UserPassAuth(*user, *pass),
		}
	}

	if *allow != "" {
		for _, raw := range strings.Split(*allow, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			ip, err := netip.ParseAddr(raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: invalid IP in -allow %q: %v\n", raw, err)
				os.Exit(1)
			}
			cfg.TrustedIPs = append(cfg.TrustedIPs, ip)
		}
	}

	srv, err := socks5.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid configuration: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg.Logger.Info("listening", "addr", *addr)
	if err := srv.ListenAndServe(ctx, *addr); err != nil {
		cfg.Logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}
