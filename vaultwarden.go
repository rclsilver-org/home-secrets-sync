package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errors.New("output size limit exceeded")
	}
	return b.buffer.Write(p)
}

type vaultSession struct {
	binary string
	env    []string
	dir    string
}

func (v *vaultSession) command(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, v.binary, args...)
	cmd.Env = v.env
	cmd.Stdin = nil
	cmd.Stderr = io.Discard // CLI diagnostics can contain sensitive values.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	output := &boundedBuffer{limit: 32 * 1024 * 1024}
	cmd.Stdout = output
	if cmd.Run() != nil {
		return nil, errors.New("Vaultwarden CLI command failed (diagnostics suppressed)")
	}
	return output.buffer.Bytes(), nil
}
func privateRAMDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("runtimeDir must be an existing private directory (mode 0700)")
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(dir, &fs) != nil || (fs.Type != 0x01021994 && fs.Type != 0x858458f6) {
		return errors.New("runtimeDir must reside on tmpfs or ramfs; refuse disk-backed CLI session storage")
	}
	return nil
}
func readVault(ctx context.Context, cfg VaultConfig) ([]Item, error) {
	if err := privateRAMDirectory(cfg.RuntimeDir); err != nil {
		return nil, err
	}
	for _, name := range []string{"BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"} {
		if os.Getenv(name) == "" {
			return nil, errors.New("BW_CLIENTID, BW_CLIENTSECRET and BW_PASSWORD are required")
		}
	}
	dir, err := os.MkdirTemp(cfg.RuntimeDir, "vaultwarden-sync-")
	if err != nil {
		return nil, errors.New("cannot create private CLI session directory")
	}
	defer os.RemoveAll(dir)
	// A fresh CLI profile prevents altering or reading the user's personal vault.
	v := vaultSession{binary: cfg.Binary, dir: dir, env: []string{
		"BITWARDENCLI_APPDATA_DIR=" + dir, "BW_NOINTERACTION=true", "HOME=" + dir, "TMPDIR=" + dir,
	}}
	for _, name := range []string{"PATH", "LANG", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"} {
		if value, ok := os.LookupEnv(name); ok {
			v.env = append(v.env, name+"="+value)
		}
	}
	if _, err = v.command(ctx, "config", "server", cfg.Server); err != nil {
		return nil, fmt.Errorf("Vaultwarden server configuration: %w", err)
	}
	if _, err = v.command(ctx, "login", "--apikey"); err != nil {
		return nil, fmt.Errorf("Vaultwarden API-key login: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = v.command(cleanup, "logout")
	}()
	session, err := v.command(ctx, "unlock", "--passwordenv", "BW_PASSWORD", "--raw")
	if err != nil || len(bytes.TrimSpace(session)) == 0 {
		return nil, errors.New("Vaultwarden unlock failed")
	}
	v.env = append(v.env, "BW_SESSION="+strings.TrimSpace(string(session)))
	clear(session)
	if _, err = v.command(ctx, "sync"); err != nil {
		return nil, fmt.Errorf("Vaultwarden cache synchronization: %w", err)
	}
	data, err := v.command(ctx, "list", "items")
	if err != nil {
		return nil, fmt.Errorf("Vaultwarden item listing: %w", err)
	}
	defer clear(data)
	var items []Item
	if json.Unmarshal(data, &items) != nil {
		return nil, errors.New("invalid Vaultwarden item response")
	}
	return items, nil
}
