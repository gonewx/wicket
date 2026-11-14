// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// releasedVersionPattern matches a released Go version as it appears in
// runtime.Version(): `go` followed by digits and dots only. Release candidates
// (`go1.27rc1`), betas and development builds (`devel +hash`) do not match, so
// they are reported rather than silently compared.
var releasedVersionPattern = regexp.MustCompile(`^go(\d+(?:\.\d+)*)$`)

// runningToolchainVersion strips the `go` prefix from a runtime.Version() string
// so it can be compared against the mise pin, which carries no prefix. The pin
// is the single source of truth, so it is never rewritten to match; anything
// that is not a plain released version is refused instead.
func runningToolchainVersion(reported string) (string, error) {
	match := releasedVersionPattern.FindStringSubmatch(reported)
	if match == nil {
		return "", fmt.Errorf("running toolchain %q is not a released version", reported)
	}
	return match[1], nil
}

// toolchainPinPattern matches the pin spellings the project accepts in
// mise.toml: the language line alone (`1.27`, tracking the latest released
// patch) or an exact released patch (`1.27.4`). Release candidates and other
// pre-release spellings do not match.
var toolchainPinPattern = regexp.MustCompile(`^1\.27(?:\.\d+)?$`)

// toolchainSatisfiesPin reports whether a running released toolchain version
// satisfies the mise pin. A line pin (`1.27`) accepts any patch of that line,
// mirroring how mise resolves a fuzzy version; an exact pin requires equality.
func toolchainSatisfiesPin(running, pin string) bool {
	if running == pin {
		return true
	}
	if strings.Count(pin, ".") == 1 {
		return strings.HasPrefix(running, pin+".")
	}
	return false
}

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
	if !toolchainPinPattern.MatchString(toolchainPin) {
		t.Fatalf("mise.toml pins go %q, want the 1.27 line (\"1.27\") or a released 1.27.N patch", toolchainPin)
	}

	// The two checks above only read declarations. This one closes the gap
	// between what is declared and what is actually compiling the tests: a
	// stale PATH entry, a leftover build cache or a forgotten `mise exec` all
	// leave the files green while the code runs on another toolchain.
	running, err := runningToolchainVersion(runtime.Version())
	if err != nil {
		t.Fatalf("%v (mise.toml pins %s)", err, toolchainPin)
	}
	if !toolchainSatisfiesPin(running, toolchainPin) {
		t.Fatalf("tests are running on go%s, which does not satisfy the mise.toml pin %s — run commands through `mise exec`", running, toolchainPin)
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

// TestRunningToolchainVersion pins how a reported toolchain version is compared
// against the pin. Only plain released versions may be normalised; every
// pre-release or development spelling must be refused so that a toolchain the
// project does not pin can never satisfy the guard by accident.
func TestRunningToolchainVersion(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		reported string
		want     string
		wantErr  bool
	}{
		"released patch version":  {reported: "go1.27.0", want: "1.27.0"},
		"released minor version":  {reported: "go1.27", want: "1.27"},
		"later patch version":     {reported: "go1.27.3", want: "1.27.3"},
		"release candidate":       {reported: "go1.27rc1", wantErr: true},
		"beta":                    {reported: "go1.28beta1", wantErr: true},
		"development build":       {reported: "devel +abc123", wantErr: true},
		"development with go tag": {reported: "go1.28-devel_abc123", wantErr: true},
		"empty":                   {reported: "", wantErr: true},
		"prefix only":             {reported: "go", wantErr: true},
		"missing prefix":          {reported: "1.27.0", wantErr: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := runningToolchainVersion(tc.reported)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("runningToolchainVersion(%q) = %q, want an error", tc.reported, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("runningToolchainVersion(%q) error = %v, want %q", tc.reported, err, tc.want)
			}
			if got != tc.want {
				t.Fatalf("runningToolchainVersion(%q) = %q, want %q", tc.reported, got, tc.want)
			}
		})
	}
}

// TestToolchainPinSpellings pins which mise.toml spellings the toolchain guard
// accepts and how a running toolchain is matched against each. The line pin
// lets local machines and CI pick up Go patch releases (bug and security fixes)
// without an edit, while still rejecting release candidates and other lines.
func TestToolchainPinSpellings(t *testing.T) {
	t.Parallel()

	for pin, ok := range map[string]bool{
		"1.27": true, "1.27.0": true, "1.27.4": true,
		"1.27rc1": false, "1.26": false, "1.28.0": false, "1": false, "1.27.x": false, "": false,
	} {
		if got := toolchainPinPattern.MatchString(pin); got != ok {
			t.Errorf("toolchainPinPattern.MatchString(%q) = %v, want %v", pin, got, ok)
		}
	}

	cases := []struct {
		running, pin string
		want         bool
	}{
		{"1.27.4", "1.27", true},
		{"1.27.0", "1.27", true},
		{"1.27", "1.27", true},
		{"1.270.1", "1.27", false},
		{"1.28.0", "1.27", false},
		{"1.27.4", "1.27.4", true},
		{"1.27.3", "1.27.4", false},
		{"1.27.40", "1.27.4", false},
	}
	for _, tc := range cases {
		if got := toolchainSatisfiesPin(tc.running, tc.pin); got != tc.want {
			t.Errorf("toolchainSatisfiesPin(%q, %q) = %v, want %v", tc.running, tc.pin, got, tc.want)
		}
	}
}
