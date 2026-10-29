package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run(ctx context.Context, filename string, apply bool) error {
	c, err := loadConfig(filename)
	if err != nil {
		return err
	}
	items, err := readVault(ctx, c.Vaultwarden)
	if err != nil {
		return err
	}
	exports, err := buildPlan(c, items)
	if err != nil {
		return err
	}
	return synchronize(ctx, c, exports, apply, os.Stdout)
}
func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	config := flag.String("config", "config.json", "non-secret destination configuration")
	apply := flag.Bool("apply", false, "write changes (default: dry-run)")
	flag.Parse()
	if *showVersion {
		fmt.Printf("home-secrets-sync %s (%s)\n", version, revision)
		return
	}
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := run(ctx, *config, *apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
