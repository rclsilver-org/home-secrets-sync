package main

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestBoundedCLIOutput(t *testing.T) {
	b := &boundedBuffer{limit: 4}
	if _, err := io.Copy(b, strings.NewReader("12345")); err == nil {
		t.Fatal("output limit bypassed")
	}
	if b.buffer.Len() > 4 {
		t.Fatal("oversized output retained")
	}
}
func TestCLIErrorRedactionAndCancellation(t *testing.T) {
	v := vaultSession{binary: "sh", env: []string{"FIXTURE=secret-fixture"}}
	if output, err := v.command(context.Background(), "-c", "printf '%s' \"$FIXTURE\" >&2; exit 1"); err == nil || output != nil || strings.Contains(err.Error(), "secret-fixture") {
		t.Fatal("CLI error leaked stderr or did not fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := v.command(ctx, "-c", "exit 0"); err == nil {
		t.Fatal("canceled command ran")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation was delayed")
	}
}
