package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

type apiClient struct {
	base, token string
	http        *http.Client
}
type apiError struct{ status int }

func (e apiError) Error() string {
	return fmt.Sprintf("Infisical request failed (HTTP %d; response suppressed)", e.status)
}
func newClient(d Destination) *apiClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // Explicit destinations; never forward credentials to ambient proxies.
	return &apiClient{base: d.URL, http: &http.Client{Timeout: 30 * time.Second, Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}
}
func (a *apiClient) request(ctx context.Context, method, endpoint string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return errors.New("cannot encode Infisical request")
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+endpoint, reader)
	if err != nil {
		return errors.New("cannot construct Infisical request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	res, err := a.http.Do(req)
	if err != nil {
		return errors.New("Infisical transport failed (details suppressed)")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return apiError{res.StatusCode}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1024*1024))
		return nil
	}
	if json.NewDecoder(io.LimitReader(res.Body, 4*1024*1024)).Decode(out) != nil {
		return errors.New("invalid Infisical JSON response")
	}
	return nil
}
func (a *apiClient) login(ctx context.Context, d Destination) error {
	id, secret := os.Getenv(d.ClientIDEnv), os.Getenv(d.ClientSecretEnv)
	if id == "" || secret == "" {
		return errors.New("Infisical Universal Auth credentials are missing")
	}
	var result struct {
		AccessToken string `json:"accessToken"`
	}
	if err := a.request(ctx, "POST", "/api/v1/auth/universal-auth/login", map[string]string{"clientId": id, "clientSecret": secret}, &result); err != nil {
		return err
	}
	if result.AccessToken == "" {
		return errors.New("Infisical login returned no access token")
	}
	a.token = result.AccessToken
	return nil
}

type targetSecret struct {
	ID      string  `json:"id"`
	Value   *string `json:"secretValue"`
	Comment string  `json:"secretComment"`
	Hidden  bool    `json:"secretValueHidden"`
}

func query(e Export) url.Values {
	return url.Values{"projectId": {e.ProjectID}, "environment": {e.Environment}, "secretPath": {e.Path}, "type": {"shared"},
		"includeImports": {"false"}, "expandSecretReferences": {"false"}, "viewSecretValue": {"true"}}
}
func (a *apiClient) folder(ctx context.Context, e Export) error {
	q := url.Values{"workspaceId": {e.ProjectID}, "environment": {e.Environment}, "path": {e.Path}}
	return a.request(ctx, "GET", "/api/v1/folders?"+q.Encode(), nil, &struct {
		Folders []any `json:"folders"`
	}{})
}
func (a *apiClient) get(ctx context.Context, e Export) (*targetSecret, error) {
	var result struct {
		Secret targetSecret `json:"secret"`
	}
	err := a.request(ctx, "GET", "/api/v4/secrets/"+url.PathEscape(e.Key)+"?"+query(e).Encode(), nil, &result)
	var status apiError
	if errors.As(err, &status) && status.status == 404 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if result.Secret.ID == "" || result.Secret.Hidden || result.Secret.Value == nil {
		return nil, errors.New("destination returned a hidden or incomplete secret")
	}
	return &result.Secret, nil
}
func (a *apiClient) write(ctx context.Context, e Export, create bool) error {
	method := "PATCH"
	if create {
		method = "POST"
	}
	body := map[string]any{"projectId": e.ProjectID, "environment": e.Environment, "secretPath": e.Path,
		"type": "shared", "secretValue": e.Value, "secretComment": e.Owner, "skipMultilineEncoding": true}
	var result struct {
		Secret targetSecret `json:"secret"`
	}
	if err := a.request(ctx, method, "/api/v4/secrets/"+url.PathEscape(e.Key), body, &result); err != nil {
		return err
	}
	if result.Secret.ID == "" {
		return errors.New("secret write not confirmed (possibly pending approval)")
	}
	return nil
}

type Summary struct {
	Mode      string `json:"mode"`
	Exports   int    `json:"exports"`
	Create    int    `json:"create"`
	Update    int    `json:"update"`
	Unchanged int    `json:"unchanged"`
	Written   int    `json:"written"`
}
type operation struct {
	export   Export
	previous *targetSecret
}

func synchronize(ctx context.Context, c Config, exports []Export, apply bool, output io.Writer) error {
	summary := Summary{Mode: "dry-run", Exports: len(exports)}
	if apply {
		summary.Mode = "apply"
	}
	clients := map[string]*apiClient{}
	folders := map[string]bool{}
	var operations []operation
	// Preflight every target before the first write, including dry-run ownership checks.
	for index, e := range exports {
		a := clients[e.Destination]
		if a == nil {
			d := c.Destinations[e.Destination]
			a = newClient(d)
			defer a.http.CloseIdleConnections()
			if err := a.login(ctx, d); err != nil {
				return err
			}
			clients[e.Destination] = a
		}
		folderID := e.Destination + "\x00" + e.ProjectID + "\x00" + e.Environment + "\x00" + e.Path
		if !folders[folderID] {
			if err := a.folder(ctx, e); err != nil {
				return fmt.Errorf("target %d folder preflight: %w", index+1, err)
			}
			folders[folderID] = true
		}
		previous, err := a.get(ctx, e)
		if err != nil {
			return fmt.Errorf("target %d preflight: %w", index+1, err)
		}
		if previous == nil {
			summary.Create++
		} else {
			if previous.Comment != e.Owner {
				return fmt.Errorf("target %d: existing secret is not owned by this export; refusing overwrite", index+1)
			}
			if *previous.Value == e.Value {
				summary.Unchanged++
				continue
			}
			summary.Update++
		}
		operations = append(operations, operation{e, previous})
	}
	if apply {
		for index, op := range operations {
			a := clients[op.export.Destination]
			// Detect intervening edits. Single-writer deployment is still required (API has no CAS).
			current, err := a.get(ctx, op.export)
			if err != nil {
				return err
			}
			if (op.previous == nil) != (current == nil) || (current != nil &&
				(current.ID != op.previous.ID || current.Comment != op.previous.Comment || *current.Value != *op.previous.Value)) {
				return errors.New("destination changed since preflight; rerun required")
			}
			if err := a.write(ctx, op.export, op.previous == nil); err != nil {
				return fmt.Errorf("write %d failed after %d successful writes: %w", index+1, summary.Written, err)
			}
			summary.Written++
		}
	}
	return json.NewEncoder(output).Encode(summary)
}
