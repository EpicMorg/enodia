// SPDX-License-Identifier: AGPL-3.0-or-later

// Command enodia is the CLI entry point: collect, check, export, config
// path|validate|resolve, products, version. completion comes free from
// cobra.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Cancels in-flight probes on ctrl-C/SIGTERM instead of leaving the
	// process to hang until every target's timeout elapses.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := rootCmd.ExecuteContext(ctx)
	if err != nil && err.Error() != "" {
		fmt.Fprintln(os.Stderr, "enodia:", err)
	}
	return exitCode(err)
}
