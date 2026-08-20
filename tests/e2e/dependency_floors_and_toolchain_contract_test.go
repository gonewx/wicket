// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// tomlTableHeaderPattern matches a TOML table header line, e.g. `[tools]`.
var tomlTableHeaderPattern = regexp.MustCompile(`^\[([^\]]*)\]\s*$`)

// goEntryPattern matches the key half of a `go` entry, bare or quoted, and
// captures whatever follows the equals sign on that line. It is anchored to the
// start of a single line: the character class excludes newlines so the key, the
// equals sign and the value cannot be spread across lines.
var goEntryPattern = regexp.MustCompile(`^[ \t]*"?go"?[ \t]*=[ \t]*([^\n]*)$`)

// scalarValuePattern matches a double-quoted scalar occupying the whole value.
var scalarValuePattern = regexp.MustCompile(`^"([^"]*)"[ \t]*(?:#.*)?$`)

// parseGoToolchainPin returns the Go version pinned under the `[tools]` table of
// a mise configuration, including platform-specific subtables such as
// `[tools.linux]`. It deliberately refuses anything it cannot read as a single
// unambiguous scalar pin rather than guessing: a `go` entry outside the tools
// tables is not a toolchain pin, two entries mean the effective one is unclear,
// and the table and array spellings carry more than one version.
func parseGoToolchainPin(config string) (string, error) {
	table := ""
	found := []string{}
	for _, line := range strings.Split(config, "\n") {
		if header := tomlTableHeaderPattern.FindStringSubmatch(strings.TrimSpace(line)); header != nil {
			table = header[1]
			continue
		}
		if table != "tools" && !strings.HasPrefix(table, "tools.") {
			continue
		}
		entry := goEntryPattern.FindStringSubmatch(line)
		if entry == nil {
			continue
		}
		value := strings.TrimSpace(entry[1])
		scalar := scalarValuePattern.FindStringSubmatch(value)
		if scalar == nil {
			return "", fmt.Errorf("go entry is not a quoted scalar version: %s", value)
		}
		found = append(found, scalar[1])
	}

	switch len(found) {
	case 0:
		return "", fmt.Errorf("no go entry under a [tools] table")
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("%d go entries under [tools] tables, want exactly 1: %s", len(found), strings.Join(found, ", "))
	}
}

// readGoToolchainPin returns the Go version pinned in mise.toml.
func readGoToolchainPin(t *testing.T) string {
	t.Helper()

	pin, err := parseGoToolchainPin(readProjectFile(t, "mise.toml"))
	if err != nil {
		t.Fatalf("read go toolchain pin from mise.toml: %v", err)
	}
	return pin
}

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

// TestToolchainVersionsArePinnedToReleasesE2E pins both halves of the toolchain
// declaration to exact released versions. The language version directive in
// go.mod is published to downstream modules; the pin in mise.toml is not
// published but decides what compiles the code locally and in CI. Matching both
// exactly is what rejects a release candidate — no rc spelling equals either
// value — and it also means a patch-level bump is a deliberate edit here rather
// than something that drifts in. The two were deliberately split while 1.27 was
// still pre-release; now that the released toolchain is pinned, one rule covers
// both.
func TestToolchainVersionsArePinnedToReleasesE2E(t *testing.T) {
	t.Parallel()

	goDirective, _ := readModuleMetadata(t)
	if goDirective != "1.27" {
		t.Fatalf("language version directive = %q, want 1.27", goDirective)
	}

	toolchainPin := readGoToolchainPin(t)
	if toolchainPin != "1.27.0" {
		t.Fatalf("mise.toml pins go %q, want the released 1.27.0 toolchain", toolchainPin)
	}
}

// TestParseGoToolchainPin pins the parser's own failure modes. The guard above
// is only as trustworthy as its ability to tell a real pin from a lookalike, so
// each case here is a spelling that must not be silently accepted or silently
// rejected.
func TestParseGoToolchainPin(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		config  string
		want    string
		wantErr string
	}{
		"released scalar pin": {
			config: "[tools]\ngo = \"1.27.0\"\n",
			want:   "1.27.0",
		},
		"pin with trailing comment": {
			config: "[tools]\ngo = \"1.27.0\" # released\n",
			want:   "1.27.0",
		},
		"quoted key": {
			config: "[tools]\n\"go\" = \"1.27.0\"\n",
			want:   "1.27.0",
		},
		"release candidate pin is read verbatim": {
			config: "[tools]\ngo = \"1.27rc1\"\n",
			want:   "1.27rc1",
		},
		"other tools are ignored": {
			config: "[tools]\nnode = \"22\"\ngo = \"1.27.0\"\nterraform = \"1.9.0rc1\"\n",
			want:   "1.27.0",
		},
		"go outside tools table is not a pin": {
			config:  "[tools]\nnode = \"22\"\n\n[env]\ngo = \"not-a-toolchain\"\n",
			wantErr: "no go entry",
		},
		"no go entry at all": {
			config:  "[tools]\nnode = \"22\"\n",
			wantErr: "no go entry",
		},
		// mise itself rejects both spellings of a repeated pin: TOML forbids
		// duplicate keys in one table, and `[tools.linux]` is the definition
		// table of a tool named linux, which mise requires to carry a version.
		// The parser still refuses ambiguity of its own accord, so that reusing
		// it on text mise never validated cannot silently pick one of two pins.
		"two pins are ambiguous rather than first-wins": {
			config:  "[tools]\ngo = \"1.27.0\"\n\n[tools.linux]\ngo = \"1.26.5\"\n",
			wantErr: "want exactly 1",
		},
		"inline table spelling is refused by name": {
			config:  "[tools]\ngo = { version = \"1.27.0\" }\n",
			wantErr: "not a quoted scalar",
		},
		"array spelling is refused by name": {
			config:  "[tools]\ngo = [\"1.27.0\", \"1.26\"]\n",
			wantErr: "not a quoted scalar",
		},
		"key and value split across lines": {
			config:  "[tools]\ngo\n=\n\"1.27.0\"\n",
			wantErr: "no go entry",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := parseGoToolchainPin(tc.config)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("parseGoToolchainPin() = %q, want error containing %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGoToolchainPin() error = %v, want %q", err, tc.want)
			}
			if got != tc.want {
				t.Fatalf("parseGoToolchainPin() = %q, want %q", got, tc.want)
			}
		})
	}
}
