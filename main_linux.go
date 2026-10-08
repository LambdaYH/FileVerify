package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"folderverify/internal/cli"
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, exe)
	stop()
	os.Exit(code)
}
