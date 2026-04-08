// SPDX-License-Identifier: Apache-2.0 OR MIT

//go:build !unix

package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
)

// upgradeSignal returns nil on non-Unix platforms; selecting on a nil channel
// blocks forever, effectively disabling the upgrade path.
func upgradeSignal() <-chan os.Signal { return nil }

// inheritListener is a no-op on non-Unix platforms.
func inheritListener() (net.Listener, error) { return nil, nil }

// signalReady is a no-op on non-Unix platforms.
func signalReady() {}

// startUpgrade is not supported on non-Unix platforms.
func startUpgrade(_ net.Listener, _ *slog.Logger) error {
	return fmt.Errorf("graceful upgrade is not supported on this platform")
}
