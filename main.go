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
	interval := flag.Duration("interval", 0, "run as a daemon, synchronizing every interval (default: run once and exit)")
	flag.Parse()
	if *showVersion {
		fmt.Printf("home-secrets-sync %s (%s)\n", version, revision)
		return
	}
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if *interval < 0 || (*interval > 0 && *interval < time.Minute) {
		fmt.Fprintln(os.Stderr, "interval must be 0 or at least 1m")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err := run(runCtx, *config, *apply)
		cancel()
		if *interval == 0 {
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
		// Daemon mode: a failed run is reported and retried at the next tick.
		if err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*interval):
		}
	}
}
