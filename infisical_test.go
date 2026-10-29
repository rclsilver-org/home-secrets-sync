package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPreflightIdempotenceOwnershipAndErrors(t *testing.T) {
	secrets := map[string]targetSecret{}
	writes := 0
	folderForbidden := false
	secretForbidden := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/auth/universal-auth/login":
			json.NewEncoder(w).Encode(map[string]string{"accessToken": "fixture-token"})
		case r.URL.Path == "/api/v1/folders":
			if folderForbidden {
				w.WriteHeader(403)
				w.Write([]byte("sensitive-server-error"))
				return
			}
			w.Write([]byte(`{"folders":[]}`))
		case strings.HasPrefix(r.URL.Path, "/api/v4/secrets/"):
			if r.Header.Get("Authorization") != "Bearer fixture-token" {
				t.Error("missing authorization")
			}
			key := strings.TrimPrefix(r.URL.Path, "/api/v4/secrets/")
			if r.Method == "GET" {
				if secretForbidden {
					w.WriteHeader(403)
					return
				}
				if r.URL.Query().Get("includeImports") != "false" || r.URL.Query().Get("expandSecretReferences") != "false" {
					t.Error("unsafe reference expansion")
				}
				v, ok := secrets[key]
				if !ok {
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"secret": v})
				return
			}
			if r.Method != "POST" && r.Method != "PATCH" {
				t.Error("unexpected mutation")
			}
			var payload struct {
				Value   string `json:"secretValue"`
				Comment string `json:"secretComment"`
			}
			json.NewDecoder(r.Body).Decode(&payload)
			writes++
			v := targetSecret{ID: key, Value: str(payload.Value), Comment: payload.Comment}
			secrets[key] = v
			json.NewEncoder(w).Encode(map[string]any{"secret": v})
		default:
			t.Errorf("unexpected endpoint: %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	c := testConfig()
	d := c.Destinations["dev"]
	d.URL = server.URL
	d.AllowInsecureHTTP = true
	c.Destinations["dev"] = d
	t.Setenv("INFISICAL_CLIENT_ID", "fixture-id")
	t.Setenv("INFISICAL_CLIENT_SECRET", "fixture-secret")
	p, err := buildPlan(c, []Item{testItem()})
	if err != nil {
		t.Fatal(err)
	}
	call := func(apply bool) (Summary, error) {
		var b bytes.Buffer
		err := synchronize(context.Background(), c, p, apply, &b)
		var s Summary
		if err == nil {
			err = json.Unmarshal(b.Bytes(), &s)
		}
		if strings.Contains(b.String(), "fixture-password") {
			t.Fatal("secret in output")
		}
		return s, err
	}
	if s, err := call(false); err != nil || s.Create != 3 || writes != 0 {
		t.Fatal("dry-run mutated destination", err)
	}
	if s, err := call(true); err != nil || s.Written != 3 || writes != 3 {
		t.Fatal("initial write failed", err)
	}
	if s, err := call(true); err != nil || s.Unchanged != 3 || writes != 3 {
		t.Fatal("idempotence failed", err)
	}
	p[0].Value = "rotated-fixture"
	if s, err := call(true); err != nil || s.Update != 1 || s.Written != 1 || writes != 4 {
		t.Fatal("rotation failed", err)
	}
	// Earlier target would change, but a later ownership conflict must prevent every write.
	p[0].Value = "next-fixture"
	last := secrets[p[2].Key]
	last.Comment = "manual-owner"
	secrets[p[2].Key] = last
	if _, err := call(true); err == nil || writes != 4 {
		t.Fatal("ownership conflict partially applied")
	}
	last.Comment = p[2].Owner
	secrets[p[2].Key] = last
	folderForbidden = true
	if _, err := call(true); err == nil || strings.Contains(err.Error(), "sensitive-server-error") || writes != 4 {
		t.Fatal("folder refusal leaked data or wrote")
	}
	folderForbidden = false
	secretForbidden = true
	if _, err := call(true); err == nil || writes != 4 {
		t.Fatal("secret read forbidden treated as absent")
	}
}
func TestRedirectNeverForwardsCredentials(t *testing.T) {
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	a := newClient(Destination{URL: redirect.URL})
	a.token = "sensitive-fixture"
	if err := a.request(context.Background(), "POST", "/login", map[string]string{"secret": "fixture"}, nil); err == nil || called {
		t.Fatal("redirect followed")
	}
}
