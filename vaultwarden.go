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
	"path/filepath"
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
func (v *vaultSession) logout() {
	cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _ = v.command(cleanup, "logout")
}

// privateStateDirectory returns the persistent CLI profile directory, creating it
// with mode 0700. It may live on disk: it holds the device identity and API tokens
// but neither the master password nor the session key, which stay in memory.
func privateStateDirectory(dir string) (string, error) {
	dir = filepath.Join(dir, "cli")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", errors.New("cannot create CLI state directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("stateDir/cli must be a private directory (mode 0700)")
	}
	return dir, nil
}

// seedDeviceID pins the CLI device identity unless the profile already has one.
func seedDeviceID(dir, id string) error {
	state, _ := json.Marshal(map[string]string{"global_applicationId_appId": id})
	f, err := os.OpenFile(filepath.Join(dir, "data.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return errors.New("cannot seed CLI device identity")
	}
	defer f.Close()
	if _, err = f.Write(state); err != nil {
		return errors.New("cannot seed CLI device identity")
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
	scratch, err := os.MkdirTemp(cfg.RuntimeDir, "vaultwarden-sync-")
	if err != nil {
		return nil, errors.New("cannot create private CLI session directory")
	}
	defer os.RemoveAll(scratch)
	// A dedicated CLI profile prevents altering or reading the user's personal vault.
	// With a stateDir the profile (device identity and login) survives between runs;
	// otherwise it lives in RAM next to the scratch files and is removed after each run.
	dir, persistent := scratch, cfg.StateDir != ""
	if persistent {
		if dir, err = privateStateDirectory(cfg.StateDir); err != nil {
			return nil, err
		}
	}
	v := vaultSession{binary: cfg.Binary, dir: dir, env: []string{
		"BITWARDENCLI_APPDATA_DIR=" + dir, "BW_NOINTERACTION=true", "HOME=" + scratch, "TMPDIR=" + scratch,
	}}
	for _, name := range []string{"PATH", "LANG", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"} {
		if value, ok := os.LookupEnv(name); ok {
			v.env = append(v.env, name+"="+value)
		}
	}
	if cfg.DeviceID != "" {
		if err = seedDeviceID(dir, cfg.DeviceID); err != nil {
			return nil, err
		}
	}
	// A persisted profile keeps its login: only (re)authenticate when needed, so the
	// device stays known to Vaultwarden and no "new device" mail is sent per run.
	loggedIn := false
	if persistent {
		if _, err = v.command(ctx, "login", "--check"); err == nil {
			// The server cannot be changed while logged in.
			current, _ := v.command(ctx, "config", "server")
			loggedIn = strings.TrimRight(strings.TrimSpace(string(current)), "/") == strings.TrimRight(cfg.Server, "/")
			if !loggedIn {
				v.logout()
			}
		}
	}
	if !loggedIn {
		if _, err = v.command(ctx, "config", "server", cfg.Server); err != nil {
			return nil, fmt.Errorf("Vaultwarden server configuration: %w", err)
		}
		if _, err = v.command(ctx, "login", "--apikey"); err != nil {
			return nil, fmt.Errorf("Vaultwarden API-key login: %w", err)
		}
	}
	// Ephemeral profiles are always logged out. A persisted one is only reset after a
	// failure (e.g. expired tokens) so the next run starts from a clean login.
	failed := true
	defer func() {
		if !persistent || failed {
			v.logout()
		}
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
	failed = false
	return items, nil
}
