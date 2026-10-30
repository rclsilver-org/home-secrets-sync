package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
)

type Config struct {
	SourceID     string                 `json:"sourceID"`
	Vaultwarden  VaultConfig            `json:"vaultwarden"`
	Destinations map[string]Destination `json:"destinations"`
}
type VaultConfig struct {
	Server     string `json:"server"`
	RuntimeDir string `json:"runtimeDir"`
	Binary     string `json:"binary"`
	// StateDir, when set, persists the CLI profile (device identity and login) across
	// runs, typically on a PVC. Empty means an ephemeral profile in RuntimeDir.
	StateDir string `json:"stateDir"`
	// DeviceID is a stable UUID presented to Vaultwarden as the CLI device.
	// Without it every run registers a new device and triggers a notification mail.
	DeviceID string `json:"deviceID"`
}
type Destination struct {
	URL               string             `json:"url"`
	AllowInsecureHTTP bool               `json:"allowInsecureHTTP"`
	ClientIDEnv       string             `json:"clientIDEnv"`
	ClientSecretEnv   string             `json:"clientSecretEnv"`
	Projects          map[string]Project `json:"projects"`
}
type Project struct {
	ID           string   `json:"id"`
	Environments []string `json:"environments"`
	PathPrefixes []string `json:"pathPrefixes"`
}

var slug = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var keyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,254}$`)
var itemID = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)

func validURL(raw string, allowHTTP bool) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		(u.Path == "" || u.Path == "/") && (u.Scheme == "https" || (allowHTTP && u.Scheme == "http"))
}
func validPath(p string) bool {
	if p == "/" {
		return true
	}
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return false
	}
	for _, part := range strings.Split(p[1:], "/") {
		if !slug.MatchString(part) {
			return false
		}
	}
	return true
}
func allowedPath(p string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix == "/" || p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
func loadConfig(filename string) (Config, error) {
	var c Config
	f, err := os.Open(filename)
	if err != nil {
		return c, errors.New("cannot open configuration")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1024*1024))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, errors.New("invalid configuration JSON (unknown fields are rejected)")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	return c, c.validate()
}
func (c *Config) validate() error {
	if !slug.MatchString(c.SourceID) || !validURL(c.Vaultwarden.Server, false) || c.Vaultwarden.RuntimeDir == "" {
		return errors.New("sourceID, HTTPS Vaultwarden server and private tmpfs runtimeDir are required")
	}
	if c.Vaultwarden.DeviceID != "" && !itemID.MatchString(c.Vaultwarden.DeviceID) {
		return errors.New("vaultwarden.deviceID must be a UUID")
	}
	if c.Vaultwarden.Binary == "" {
		c.Vaultwarden.Binary = "bw"
	}
	if len(c.Destinations) == 0 {
		return errors.New("at least one destination is required")
	}
	for alias, dest := range c.Destinations {
		if !slug.MatchString(alias) || !validURL(dest.URL, dest.AllowInsecureHTTP) || len(dest.Projects) == 0 {
			return errors.New("invalid destination alias, origin URL or project allowlist")
		}
		dest.URL = strings.TrimSuffix(dest.URL, "/")
		if dest.ClientIDEnv == "" {
			dest.ClientIDEnv = "INFISICAL_CLIENT_ID"
		}
		if dest.ClientSecretEnv == "" {
			dest.ClientSecretEnv = "INFISICAL_CLIENT_SECRET"
		}
		if !envName.MatchString(dest.ClientIDEnv) || !envName.MatchString(dest.ClientSecretEnv) {
			return errors.New("invalid credential environment variable name")
		}
		for name, project := range dest.Projects {
			if !slug.MatchString(name) || project.ID == "" || len(project.Environments) == 0 || len(project.PathPrefixes) == 0 {
				return errors.New("each project needs an alias, ID, environments and pathPrefixes allowlists")
			}
			for _, e := range project.Environments {
				if !slug.MatchString(e) {
					return errors.New("invalid allowed environment")
				}
			}
			for _, p := range project.PathPrefixes {
				if !validPath(p) {
					return errors.New("invalid allowed path prefix")
				}
			}
		}
		c.Destinations[alias] = dest
	}
	return nil
}
