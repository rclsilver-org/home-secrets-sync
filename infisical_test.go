package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path"
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
			if r.URL.Query().Get("path") == "/" {
				w.Write([]byte(`{"folders":[{"id":"aiga-id","name":"aiga"}]}`))
			} else {
				w.Write([]byte(`{"folders":[]}`))
			}
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

func TestMissingFolders(t *testing.T) {
	for _, scenario := range []string{"nested", "existing ancestor", "forbidden read", "forbidden create", "partial failure", "missing environment", "outside allowlist", "late ownership conflict"} {
		t.Run(scenario, func(t *testing.T) {
			folders := map[string]bool{"/": true}
			secrets := map[string]targetSecret{}
			var created []string
			secretWrites := 0
			if scenario == "existing ancestor" || scenario == "late ownership conflict" {
				folders["/aiga"] = true
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/api/v1/auth/universal-auth/login":
					json.NewEncoder(w).Encode(map[string]string{"accessToken": "fixture-token"})
				case r.URL.Path == "/api/v1/folders" && r.Method == "GET":
					if scenario == "forbidden read" || scenario == "missing environment" {
						status := 403
						if scenario == "missing environment" {
							status = 404
						}
						w.WriteHeader(status)
						w.Write([]byte("sensitive-server-error"))
						return
					}
					children := []targetFolder{}
					parent := r.URL.Query().Get("path")
					for name := range folders {
						if name != "/" && path.Dir(name) == parent {
							children = append(children, targetFolder{ID: name, Name: path.Base(name)})
						}
					}
					// Real Infisical also returns [] for nonexistent paths.
					json.NewEncoder(w).Encode(map[string]any{"folders": children})
				case r.URL.Path == "/api/v1/folders" && r.Method == "POST":
					if scenario == "forbidden create" || (scenario == "partial failure" && len(created) == 1) {
						w.WriteHeader(403)
						return
					}
					var payload struct {
						Project                 string `json:"workspaceId"`
						Environment, Path, Name string
					}
					json.NewDecoder(r.Body).Decode(&payload)
					if payload.Project != "project-id" || payload.Environment != "production" || !folders[payload.Path] {
						t.Error("invalid folder routing or parent creation order")
					}
					name := path.Join(payload.Path, payload.Name)
					if folders[name] {
						t.Error("duplicate folder creation")
					}
					folders[name] = true
					created = append(created, name)
					json.NewEncoder(w).Encode(map[string]any{"folder": targetFolder{ID: name, Name: payload.Name}})
				case strings.HasPrefix(r.URL.Path, "/api/v4/secrets/"):
					key := strings.TrimPrefix(r.URL.Path, "/api/v4/secrets/")
					if r.Method == "GET" {
						folder := r.URL.Query().Get("secretPath")
						if !folders[folder] {
							t.Error("secret requested before folder exists")
						}
						if scenario == "late ownership conflict" && folder == "/aiga" {
							json.NewEncoder(w).Encode(map[string]any{"secret": targetSecret{ID: "manual", Value: str("sensitive-fixture"), Comment: "manual"}})
							return
						}
						secret, ok := secrets[folder+"/"+key]
						if !ok {
							w.WriteHeader(404)
							return
						}
						json.NewEncoder(w).Encode(map[string]any{"secret": secret})
						return
					}
					var payload struct{ SecretPath, SecretValue, SecretComment string }
					json.NewDecoder(r.Body).Decode(&payload)
					if !folders[payload.SecretPath] {
						t.Error("secret written before folder exists")
					}
					secretWrites++
					secret := targetSecret{ID: key, Value: str(payload.SecretValue), Comment: payload.SecretComment}
					secrets[payload.SecretPath+"/"+key] = secret
					json.NewEncoder(w).Encode(map[string]any{"secret": secret})
				default:
					t.Error("unexpected API request")
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			c := testConfig()
			d := c.Destinations["dev"]
			d.URL, d.AllowInsecureHTTP = server.URL, true
			if scenario == "outside allowlist" {
				project := d.Projects["backend-secrets"]
				project.PathPrefixes = []string{"/aiga/nested"}
				d.Projects["backend-secrets"] = project
				// Another alias for the same project must not broaden this export's scope.
				broader := project
				broader.PathPrefixes = []string{"/"}
				d.Projects["other-project-alias"] = broader
			}
			c.Destinations["dev"] = d
			t.Setenv("INFISICAL_CLIENT_ID", "fixture-id")
			t.Setenv("INFISICAL_CLIENT_SECRET", "fixture-secret")
			i := testItem()
			setMeta(&i, "sync.path", "/aiga/nested")
			p, err := buildPlan(c, []Item{i})
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "late ownership conflict" {
				last := p[0]
				last.Path = "/aiga"
				p = append(p, last)
			}
			call := func(apply bool) (Summary, error) {
				var out bytes.Buffer
				err := synchronize(context.Background(), c, p, apply, &out)
				if strings.Contains(out.String(), "fixture-password") || (err != nil && strings.Contains(err.Error(), "sensitive")) {
					t.Fatal("sensitive data leaked")
				}
				var report Summary
				if err == nil {
					err = json.Unmarshal(out.Bytes(), &report)
				}
				return report, err
			}
			if scenario != "nested" && scenario != "existing ancestor" && scenario != "forbidden create" && scenario != "partial failure" {
				if _, err := call(true); err == nil || len(created) != 0 || secretWrites != 0 {
					t.Fatal("preflight error allowed mutations", err)
				}
				return
			}
			want := 2
			if scenario == "existing ancestor" {
				want = 1
			}
			if s, err := call(false); err != nil || s.FoldersCreate != want || s.FoldersCreated != 0 || s.Create != 3 || len(created) != 0 || secretWrites != 0 {
				t.Fatal("missing-folder dry-run failed", s, err)
			}
			if scenario == "forbidden create" {
				if _, err := call(true); err == nil || len(created) != 0 || secretWrites != 0 {
					t.Fatal("folder create refusal ignored")
				}
				return
			}
			if scenario == "partial failure" {
				if _, err := call(true); err == nil || len(created) != 1 || !folders["/aiga"] || secretWrites != 0 {
					t.Fatal("partial folder failure wrote secrets or lost the created folder")
				}
				return
			}
			if s, err := call(true); err != nil || s.FoldersCreated != want || s.Written != 3 || len(created) != want || secretWrites != 3 {
				t.Fatal("folder/secret creation failed", s, err)
			}
			if s, err := call(true); err != nil || s.FoldersCreate != 0 || s.FoldersCreated != 0 || s.Unchanged != 3 || len(created) != want || secretWrites != 3 {
				t.Fatal("folder creation is not idempotent", s, err)
			}
		})
	}
}

func TestConcurrentFolderCreation(t *testing.T) {
	for _, status := range []int{400, 409, 403, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			created := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "GET" {
					folders := []targetFolder{}
					if created {
						folders = append(folders, targetFolder{ID: "id", Name: "aiga"})
					}
					json.NewEncoder(w).Encode(map[string]any{"folders": folders})
					return
				}
				created = true
				w.WriteHeader(status)
			}))
			defer server.Close()
			a := newClient(Destination{URL: server.URL})
			defer a.http.CloseIdleConnections()
			made, err := a.createFolder(context.Background(), folderOperation{export: Export{Path: "/"}, name: "aiga"})
			if made || ((status == 400 || status == 409) != (err == nil)) {
				t.Fatal("incorrect concurrent-creation handling", made, err)
			}
		})
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
