package main

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type Field struct {
	Name  string  `json:"name"`
	Value *string `json:"value"`
	Type  int     `json:"type"`
}
type Item struct {
	ID          string  `json:"id"`
	DeletedDate *string `json:"deletedDate"`
	Reprompt    int     `json:"reprompt"`
	Notes       *string `json:"notes"`
	Fields      []Field `json:"fields"`
	Login       *struct {
		Username *string `json:"username"`
		Password *string `json:"password"`
		URIs     []struct {
			URI *string `json:"uri"`
		} `json:"uris"`
	} `json:"login"`
}
type Export struct {
	Destination, ProjectAlias, ProjectID, Environment, Path, Key, Value, Owner string
}

func resolve(item Item, selector string) (*string, error) {
	switch selector {
	case "login.username":
		if item.Login != nil {
			return item.Login.Username, nil
		}
	case "login.password":
		if item.Login != nil {
			return item.Login.Password, nil
		}
	case "notes":
		return item.Notes, nil
	default:
		if strings.HasPrefix(selector, "field:") {
			name := strings.TrimPrefix(selector, "field:")
			if name == "" || strings.HasPrefix(name, "sync.") {
				return nil, errors.New("invalid custom field source")
			}
			var result *string
			found := false
			for _, f := range item.Fields {
				if f.Name != name {
					continue
				}
				if found || f.Type == 3 {
					return nil, errors.New("ambiguous or linked custom field source")
				}
				result, found = f.Value, true
			}
			return result, nil
		}
		if strings.HasPrefix(selector, "login.uris[") && strings.HasSuffix(selector, "].uri") {
			raw := strings.TrimSuffix(strings.TrimPrefix(selector, "login.uris["), "].uri")
			i, err := strconv.Atoi(raw)
			if err != nil || i < 0 || strconv.Itoa(i) != raw {
				return nil, errors.New("invalid URI index")
			}
			if item.Login != nil && i < len(item.Login.URIs) {
				return item.Login.URIs[i].URI, nil
			}
			return nil, nil
		}
		return nil, errors.New("unsupported source selector")
	}
	return nil, nil
}

// All source validation and collision detection complete before any destination write.
func buildPlan(c Config, items []Item) ([]Export, error) {
	var exports []Export
	seen := map[string]bool{}
	for index, item := range items {
		if item.DeletedDate != nil {
			continue
		}
		enabled := false
		for _, f := range item.Fields {
			if f.Name == "sync.enabled" && f.Value != nil && *f.Value == "true" {
				enabled = true
			}
		}
		if !enabled {
			continue
		}
		fail := func(reason string) ([]Export, error) { return nil, fmt.Errorf("source item %d: %s", index+1, reason) }
		if !itemID.MatchString(item.ID) || item.Reprompt != 0 {
			return fail("invalid ID or master-password reprompt enabled")
		}
		meta := map[string]string{}
		for _, f := range item.Fields {
			if !strings.HasPrefix(f.Name, "sync.") {
				continue
			}
			if _, ok := meta[f.Name]; ok {
				return fail("duplicate sync metadata")
			}
			if f.Value == nil || f.Type == 3 {
				return fail("null or linked sync metadata")
			}
			if !strings.HasPrefix(f.Name, "sync.export.") && !contains([]string{"sync.enabled", "sync.destination", "sync.project", "sync.environment", "sync.path", "sync.allow-empty"}, f.Name) {
				return fail("unknown sync metadata")
			}
			meta[f.Name] = *f.Value
		}
		alias, projectAlias := meta["sync.destination"], meta["sync.project"]
		dest, ok := c.Destinations[alias]
		if !ok {
			return fail("destination is not configured")
		}
		project, ok := dest.Projects[projectAlias]
		if !ok {
			return fail("project is not allowed")
		}
		environment, present := meta["sync.environment"]
		if !present {
			environment = "production"
		}
		if !contains(project.Environments, environment) {
			return fail("environment is not allowed")
		}
		folder := meta["sync.path"]
		if !validPath(folder) || !allowedPath(folder, project.PathPrefixes) {
			return fail("path is invalid or not allowed")
		}
		allowEmpty := meta["sync.allow-empty"] == "true"
		if v, ok := meta["sync.allow-empty"]; ok && v != "true" && v != "false" {
			return fail("sync.allow-empty must be true or false")
		}
		count := 0
		for name, selector := range meta {
			if !strings.HasPrefix(name, "sync.export.") {
				continue
			}
			key := strings.TrimPrefix(name, "sync.export.")
			if !keyName.MatchString(key) {
				return fail("invalid export key")
			}
			value, err := resolve(item, selector)
			if err != nil {
				return fail("invalid source selector or ambiguous custom field")
			}
			if value == nil {
				return fail("an exported source field is missing")
			}
			if *value == "" && !allowEmpty {
				return fail("empty source requires sync.allow-empty=true")
			}
			// Physical destination, not its alias: two aliases cannot bypass collision checks.
			identity := strings.Join([]string{strings.ToLower(dest.URL), project.ID, environment, folder, key}, "\x00")
			if seen[identity] {
				return fail("multiple exports target the same secret")
			}
			seen[identity] = true
			exports = append(exports, Export{Destination: alias, ProjectAlias: projectAlias, ProjectID: project.ID,
				Environment: environment, Path: folder, Key: key, Value: *value,
				Owner: "vaultwarden-sync:v1:" + c.SourceID + ":" + item.ID + ":" + key})
			count++
		}
		if count == 0 {
			return fail("no sync.export.* fields")
		}
	}
	sort.Slice(exports, func(i, j int) bool {
		a, b := exports[i], exports[j]
		return strings.Join([]string{a.Destination, a.ProjectID, a.Environment, a.Path, a.Key}, "\x00") < strings.Join([]string{b.Destination, b.ProjectID, b.Environment, b.Path, b.Key}, "\x00")
	})
	return exports, nil
}
