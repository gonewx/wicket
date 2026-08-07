// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// readModuleMetadata returns the language version directive and the direct
// requires declared in go.mod. Direct requires are the dependency floors
// published to downstream modules; transitive lines are MVS-resolved and do
// not bind consumers.
func readModuleMetadata(t *testing.T) (string, map[string]string) {
	t.Helper()

	output := runCommand(t, projectRoot(t), "go", "mod", "edit", "-json")
	var parsed struct {
		Go      string `json:"Go"`
		Require []struct {
			Path     string `json:"Path"`
			Version  string `json:"Version"`
			Indirect bool   `json:"Indirect"`
		} `json:"Require"`
	}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("decode go mod edit output: %v", err)
	}

	direct := map[string]string{}
	for _, require := range parsed.Require {
		if !require.Indirect {
			direct[require.Path] = require.Version
		}
	}
	return parsed.Go, direct
}

// TestDependencyMajorVersionFloorsE2E pins the declared dependency floors.
// Each floor binds downstream version resolution through the module graph, so
// raising one is a deliberate release decision that must update this guard in
// the same change rather than arriving as a transitive side effect.
func TestDependencyMajorVersionFloorsE2E(t *testing.T) {
	t.Parallel()

	_, direct := readModuleMetadata(t)

	wantFloors := map[string]string{
		"github.com/lestrrat-go/jwx/v3":    "v3.2.0",
		"github.com/lestrrat-go/httprc/v3": "v3.0.6",
		"github.com/google/uuid":           "v1.6.0",
		"github.com/tidwall/gjson":         "v1.19.0",
	}
	for path, wantVersion := range wantFloors {
		gotVersion, ok := direct[path]
		if !ok {
			t.Fatalf("go.mod does not declare %s as a direct dependency (want floor %s)", path, wantVersion)
		}
		if gotVersion != wantVersion {
			t.Fatalf("go.mod declares %s %s, want floor %s", path, gotVersion, wantVersion)
		}
	}
}

// TestLanguageVersionDirectiveCarriesNoRCVersionE2E pins the toolchain split:
// the language version directive in go.mod is published to downstream modules
// and must never carry a release candidate, while the actual toolchain pin
// stays in mise.toml, which is not published.
func TestLanguageVersionDirectiveCarriesNoRCVersionE2E(t *testing.T) {
	t.Parallel()

	goDirective, _ := readModuleMetadata(t)
	if goDirective != "1.27" {
		t.Fatalf("language version directive = %q, want 1.27 (no release candidate)", goDirective)
	}

	toolchain := readProjectFile(t, "mise.toml")
	if !strings.Contains(toolchain, `go = "1.27rc1"`) {
		t.Fatalf("mise.toml does not pin the release candidate toolchain:\n%s", toolchain)
	}
}
