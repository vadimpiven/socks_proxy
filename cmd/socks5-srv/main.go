// SPDX-License-Identifier: Apache-2.0 OR MIT

// Command socks5-srv starts a lightweight SOCKS5 proxy server.
//
// It supports TCP CONNECT and UDP ASSOCIATE through IPv4 and IPv6 networks,
// with optional username/password authentication per RFC 1928 and RFC 1929.
//
// On first run the server creates a default configuration file
// (socks5-srv.toml) with documented settings. The default config enables
// password authentication with an empty user list, which denies all
// connections until the operator adds at least one user.
//
// Send SIGHUP to reload the configuration without dropping active sessions.
//
// Send SIGUSR2 to perform a zero-downtime binary upgrade (Unix only).
// The server re-executes the on-disk binary, passes the listening socket
// to the new process, then drains active connections and exits.
//
// Usage:
//
//	socks5-srv [flags]
//	  -config   socks5-srv.toml   path to TOML configuration file
//	  -verbose                    enable verbose log output
//	  -version                    print version and exit
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/vadimpiven/socks5-srv/socks5"
)

var version = "dev"

// config is the top-level TOML configuration.
// User entries use [socks5.User] directly so field names are shared between
// the library API and the config file.
type config struct {
	Addr  string                 `toml:"addr"`
	Bind  string                 `toml:"bind"`
	Users map[string]socks5.User `toml:"users"`
}

const defaultConfig = `# socks5-srv configuration
# https://github.com/vadimpiven/socks5-srv
#
# Send SIGHUP to reload without dropping active sessions.
# Send SIGUSR2 for a zero-downtime binary upgrade (Unix only).

# Listen address (host:port).
addr = ":1080"

# Network interface for outbound connections (default: OS routing).
# The server resolves the interface to an IP matching each destination's
# address family (IPv4 or IPv6) per connection, similar to curl --interface.
# bind = "eth0"

# User list. Presence of this section enables username/password authentication.
# An empty section denies all connections — add at least one user to accept traffic.
# Remove or comment out the entire [users] section for no-auth mode.
#
# The key is a human-readable ID. If "login" is omitted it defaults to the key.
[users]
# alice = { login = "xK9mW2pQ", password = "s3cr3t", allow_private = true }
# bob   = { password = "hunter2" }
`

func main() {
	configPath := flag.String("config", "socks5-srv.toml", "path to configuration file")
	verbose := flag.Bool("verbose", false, "enable verbose log output")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("socks5-srv " + version)
		return
	}

	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		if err := os.WriteFile(*configPath, []byte(defaultConfig), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot create config: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "created default config: %s (edit and restart)\n", *configPath)
	}

	logLevel := slog.LevelWarn
	if *verbose {
		logLevel = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	upgrade := upgradeSignal()

	// Check for a listener inherited from a parent process (graceful upgrade).
	ln, err := inheritListener()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	for {
		srv, err := buildServer(cfg, logger)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		if ln == nil {
			ln, err = net.Listen("tcp", cfg.Addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		}

		srvCtx, srvCancel := context.WithCancel(ctx)
		srvDone := make(chan error, 1)
		go func() {
			srvDone <- srv.Serve(srvCtx, ln)
		}()

		signalReady() // tell parent (if any) that we are accepting
		logger.Warn("listening", "addr", ln.Addr())

		action := ""
		for action == "" {
			select {
			case <-ctx.Done():
				srvCancel()
				<-srvDone
				return
			case err := <-srvDone:
				if err != nil {
					logger.Error("fatal", "err", err)
				}
				os.Exit(1)
			case <-sighup:
				newCfg, err := loadConfig(*configPath)
				if err != nil {
					logger.Error("reload failed", "err", err)
					break // re-enter select, keep running old config
				}
				cfg = newCfg
				action = "reload"
			case <-upgrade:
				if err := startUpgrade(ln, logger); err != nil {
					logger.Error("upgrade failed", "err", err)
					break // re-enter select, keep running
				}
				action = "upgrade"
			}
		}

		// Stop accepting new connections.
		ln.Close()
		ln = nil

		switch action {
		case "reload":
			// Drain active sessions in background while new config takes effect.
			go func(cancel context.CancelFunc, done <-chan error) {
				<-done
				cancel()
			}(srvCancel, srvDone)
			logger.Warn("configuration reloaded")
		case "upgrade":
			// Wait for all active sessions to finish, then exit.
			logger.Warn("upgrade: draining active connections")
			<-srvDone
			srvCancel()
			return
		}
	}
}

// loadConfig reads and validates the TOML configuration file.
// User-level validation (empty passwords, duplicate logins) is handled by
// [socks5.NewServer] so the library and CLI share the same rules.
func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}
	var cfg config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return config{}, err
	}
	if cfg.Addr == "" {
		cfg.Addr = ":1080"
	}
	if cfg.Bind != "" {
		if _, err := net.InterfaceByName(cfg.Bind); err != nil {
			return config{}, fmt.Errorf("bind interface %q: %w", cfg.Bind, err)
		}
	}
	return cfg, nil
}

// buildServer creates a socks5.Server from the validated configuration.
func buildServer(cfg config, logger *slog.Logger) (*socks5.Server, error) {
	scfg := socks5.Config{
		Logger: logger,
		Users:  cfg.Users,
	}
	if cfg.Bind != "" {
		scfg.Dial = ifaceDial(cfg.Bind)
	}
	if cfg.Users == nil {
		scfg.Authenticator = socks5.NoAuthAuthenticator{}
	}
	return socks5.NewServer(scfg)
}

// ifaceAddr returns the first address on iface that matches the given network
// ("tcp4" or "tcp6"). Returns nil when no address of that family exists.
func ifaceAddr(iface *net.Interface, network string) net.Addr {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	wantV4 := network == "tcp4"
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if (ip.To4() != nil) == wantV4 {
			return &net.TCPAddr{IP: ip}
		}
	}
	return nil
}

// ifaceDial returns a DialFunc that binds outgoing connections to the named
// network interface, selecting an IP matching the destination's address family.
func ifaceDial(ifaceName string) socks5.DialFunc {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("bind interface %q: %w", ifaceName, err)
		}

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// Resolve destination to determine address family.
		var dstIP net.IP
		if ip := net.ParseIP(host); ip != nil {
			dstIP = ip
		} else {
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if ip.To4() != nil {
					dstIP = ip
					break
				}
				if dstIP == nil {
					dstIP = ip
				}
			}
		}
		if dstIP == nil {
			return nil, fmt.Errorf("no addresses for %s", host)
		}

		dstNetwork := "tcp4"
		if dstIP.To4() == nil {
			dstNetwork = "tcp6"
		}

		localAddr := ifaceAddr(iface, dstNetwork)
		d := net.Dialer{LocalAddr: localAddr}
		return d.DialContext(ctx, dstNetwork, net.JoinHostPort(dstIP.String(), port))
	}
}
