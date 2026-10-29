package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func str(v string) *string { return &v }
func testConfig() Config {
	c := Config{SourceID: "fixture", Vaultwarden: VaultConfig{Server: "https://vaultwarden.invalid", RuntimeDir: "/scratch"},
		Destinations: map[string]Destination{"dev": {URL: "https://infisical.invalid", Projects: map[string]Project{
			"backend-secrets": {ID: "project-id", Environments: []string{"production", "dev"}, PathPrefixes: []string{"/aiga"}},
		}}}}
	if err := c.validate(); err != nil {
		panic(err)
	}
	return c
}
func testItem() Item {
	var i Item
	if err := json.Unmarshal([]byte(`{"id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","login":{"username":"fixture-user","password":"fixture-password","uris":[{"uri":"https://example.invalid"}]},"fields":[{"name":"sync.enabled","value":"true"},{"name":"sync.destination","value":"dev"},{"name":"sync.project","value":"backend-secrets"},{"name":"sync.path","value":"/aiga"},{"name":"sync.export.URL","value":"login.uris[0].uri"},{"name":"sync.export.USERNAME","value":"login.username"},{"name":"sync.export.PASSWORD","value":"login.password"}]}`), &i); err != nil {
		panic(err)
	}
	return i
}
func setMeta(i *Item, k, v string) {
	for n := range i.Fields {
		if i.Fields[n].Name == k {
			i.Fields[n].Value = str(v)
			return
		}
	}
	i.Fields = append(i.Fields, Field{Name: k, Value: str(v)})
}
func TestPlanMultipleExportsAndDefault(t *testing.T) {
	p, err := buildPlan(testConfig(), []Item{testItem()})
	if err != nil || len(p) != 3 {
		t.Fatalf("expected three exports: %v", err)
	}
	values := map[string]string{}
	for _, e := range p {
		if e.Environment != "production" || e.Path != "/aiga" {
			t.Fatal("incorrect routing")
		}
		values[e.Key] = e.Value
	}
	if values["PASSWORD"] != "fixture-password" || values["USERNAME"] != "fixture-user" || values["URL"] != "https://example.invalid" {
		t.Fatal("incorrect source resolution")
	}
}
func TestPlanRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Item)
	}{
		{"missing", func(i *Item) { i.Login.Password = nil }},
		{"empty", func(i *Item) { i.Login.Password = str("") }},
		{"unknown destination", func(i *Item) { setMeta(i, "sync.destination", "unconfigured") }},
		{"unknown project", func(i *Item) { setMeta(i, "sync.project", "unconfigured") }},
		{"unknown environment", func(i *Item) { setMeta(i, "sync.environment", "unconfigured") }},
		{"empty explicit environment", func(i *Item) { setMeta(i, "sync.environment", "") }},
		{"traversal", func(i *Item) { setMeta(i, "sync.path", "/aiga/../other") }},
		{"prefix bypass", func(i *Item) { setMeta(i, "sync.path", "/aiga-extra") }},
		{"selector injection", func(i *Item) { setMeta(i, "sync.export.PASSWORD", "login.password; $(id)") }},
		{"negative URI", func(i *Item) { setMeta(i, "sync.export.URL", "login.uris[-1].uri") }},
		{"missing URI", func(i *Item) { setMeta(i, "sync.export.URL", "login.uris[1].uri") }},
		{"bad key", func(i *Item) { setMeta(i, "sync.export.bad/key", "notes") }},
		{"unknown metadata", func(i *Item) { setMeta(i, "sync.environmnt", "dev") }},
		{"duplicate metadata", func(i *Item) { i.Fields = append(i.Fields, i.Fields[0]) }},
		{"ambiguous custom field", func(i *Item) {
			setMeta(i, "sync.export.PASSWORD", "field:API_TOKEN")
			i.Fields = append(i.Fields, Field{Name: "API_TOKEN", Value: str("one")}, Field{Name: "API_TOKEN", Value: str("two")})
		}},
		{"linked custom field", func(i *Item) {
			setMeta(i, "sync.export.PASSWORD", "field:API_TOKEN")
			i.Fields = append(i.Fields, Field{Name: "API_TOKEN", Value: str("one"), Type: 3})
		}},
		{"reprompt", func(i *Item) { i.Reprompt = 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := testItem()
			tt.mutate(&i)
			p, err := buildPlan(testConfig(), []Item{i})
			if err == nil || p != nil {
				t.Fatal("expected validation failure and no plan")
			}
			if strings.Contains(err.Error(), "fixture-password") || strings.Contains(err.Error(), "$(id)") {
				t.Fatal("input leaked in diagnostics")
			}
		})
	}
}
func TestEmptyCustomFieldsAndEnvironment(t *testing.T) {
	i := testItem()
	i.Login.Password = str("")
	setMeta(&i, "sync.allow-empty", "true")
	setMeta(&i, "sync.environment", "dev")
	setMeta(&i, "sync.export.TOKEN", "field:API_TOKEN")
	i.Fields = append(i.Fields, Field{Name: "API_TOKEN", Value: str("multiline\n$literal\\value")})
	p, err := buildPlan(testConfig(), []Item{i})
	if err != nil || len(p) != 4 {
		t.Fatalf("explicit empty/custom field failed: %v", err)
	}
	for _, e := range p {
		if e.Environment != "dev" {
			t.Fatal("environment override ignored")
		}
		if e.Key == "TOKEN" && e.Value != "multiline\n$literal\\value" {
			t.Fatal("value changed")
		}
	}
	i.Fields[len(i.Fields)-1].Value = nil
	if _, err = buildPlan(testConfig(), []Item{i}); err == nil {
		t.Fatal("allow-empty must not accept a missing field")
	}
}
func TestCollisionAndDisabledItems(t *testing.T) {
	i := testItem()
	j := testItem()
	j.ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	c := testConfig()
	c.Destinations["second-alias"] = c.Destinations["dev"]
	setMeta(&j, "sync.destination", "second-alias")
	if _, err := buildPlan(c, []Item{i, j}); err == nil {
		t.Fatal("alias collision accepted")
	}
	setMeta(&j, "sync.enabled", "false")
	if p, err := buildPlan(c, []Item{i, j}); err != nil || len(p) != 3 {
		t.Fatal("disabled item not ignored")
	}
	setMeta(&j, "sync.enabled", "true")
	j.DeletedDate = str("2026-01-01")
	if p, err := buildPlan(c, []Item{i, j}); err != nil || len(p) != 3 {
		t.Fatal("trashed item not ignored")
	}
}
func TestConfigAndDiskRefusal(t *testing.T) {
	for _, raw := range []string{"http://example.invalid", "https://user:password@example.invalid", "https://example.invalid/path", "https://example.invalid?token=secret", "https://example.invalid/#fragment"} {
		if validURL(raw, false) {
			t.Fatal("unsafe origin accepted")
		}
	}
	if err := privateRAMDirectory(t.TempDir()); err == nil {
		t.Fatal("disk-backed runtime accepted")
	}
}
