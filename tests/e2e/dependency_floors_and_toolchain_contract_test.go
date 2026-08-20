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

// TestToolchainVersionsCarryNoRCVersionE2E pins both halves of the toolchain
// declaration against release candidates: the language version directive in
// go.mod is published to downstream modules and must never carry one, and the
// toolchain pin in mise.toml — while not published — must stay on a released
// version so local and CI builds remain reproducible. The two were
// deliberately split while 1.27 was still pre-release; now that the released
// toolchain is pinned, the same rule covers both.
func TestToolchainVersionsCarryNoRCVersionE2E(t *testing.T) {
	t.Parallel()

	goDirective, _ := readModuleMetadata(t)
	if goDirective != "1.27" {
		t.Fatalf("language version directive = %q, want 1.27", goDirective)
	}
	if strings.Contains(goDirective, "rc") {
		t.Fatalf("language version directive %q carries a release candidate marker", goDirective)
	}

	toolchain := readProjectFile(t, "mise.toml")
	if !strings.Contains(toolchain, `go = "1.27.0"`) {
		t.Fatalf("mise.toml does not pin the released 1.27.0 toolchain:\n%s", toolchain)
	}
	if strings.Contains(toolchain, "rc") {
		t.Fatalf("mise.toml pins a release candidate toolchain:\n%s", toolchain)
	}
}
