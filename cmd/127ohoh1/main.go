// Command 127ohoh1 exposes a local HTTP origin through a public HTTPS URL.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/127ohoh1/core/client/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], cli.OSEnv())
	stop()
	os.Exit(code)
}
