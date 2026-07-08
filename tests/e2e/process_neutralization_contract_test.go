package e2e_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	configoptions "github.com/gonewx/wicket/config/options"
)

func TestTrackedPathsAndE2ENamesUseNeutralTerminologyE2E(t *testing.T) {
	t.Parallel()

	for _, rel := range trackedProjectPaths(t) {
		assertNeutralProcessName(t, rel, rel)
	}

	for _, rel := range goFiles(t) {
		if !strings.HasPrefix(rel, "tests/e2e/") || !strings.HasSuffix(rel, "_test.go") {
			continue
		}
		assertNeutralProcessName(t, rel, filepath.Base(rel))
		for _, name := range testFunctionNames(t, rel) {
			assertNeutralProcessName(t, rel, name)
		}
	}
}

func TestNeutralConfigurationOptionSurfaceE2E(t *testing.T) {
	t.Parallel()

	opts := configoptions.NewWicketOptions()
	optionFields := []struct {
		name        string
		fieldType   reflect.Type
		defaultOff  bool
		constructor any
	}{
		{
			name:        "KeyManagement",
			fieldType:   reflect.TypeOf(&configoptions.KeyManagementOptions{}),
			defaultOff:  opts.KeyManagement != nil && !opts.KeyManagement.Enabled,
			constructor: configoptions.NewKeyManagementOptions,
		},
		{
			name:        "DynamicProviders",
			fieldType:   reflect.TypeOf(&configoptions.DynamicProviderOptions{}),
			defaultOff:  opts.DynamicProviders != nil && !opts.DynamicProviders.Enabled,
			constructor: configoptions.NewDynamicProviderOptions,
		},
		{
			name:        "ServerSideSessions",
			fieldType:   reflect.TypeOf(&configoptions.ServerSideSessionOptions{}),
			defaultOff:  opts.ServerSideSessions != nil && !opts.ServerSideSessions.Enabled,
			constructor: configoptions.NewServerSideSessionOptions,
		},
	}

	wicketType := reflect.TypeOf(*opts)
	for _, tt := range optionFields {
		field, ok := wicketType.FieldByName(tt.name)
		if !ok {
			t.Fatalf("WicketOptions missing neutral field %s", tt.name)
		}
		if field.Type != tt.fieldType {
			t.Fatalf("WicketOptions.%s type = %v, want %v", tt.name, field.Type, tt.fieldType)
		}
		if !tt.defaultOff {
			t.Fatalf("WicketOptions.%s is not initialized disabled by default", tt.name)
		}
		if reflect.ValueOf(tt.constructor).Kind() != reflect.Func {
			t.Fatalf("%s constructor is not callable", tt.name)
		}
	}

	legacyPrefix := "Clean" + "Room"
	legacySuffix := "Gap"
	for _, legacyField := range []string{
		legacyPrefix + "Key" + legacySuffix,
		legacyPrefix + "Provider" + legacySuffix,
		legacyPrefix + "Session" + legacySuffix,
	} {
		if _, ok := wicketType.FieldByName(legacyField); ok {
			t.Fatalf("WicketOptions still exposes legacy field %s", legacyField)
		}
	}

	for _, rel := range []string{
		"config/options/backchannel_authentication_options.go",
		"config/options/wicket_options.go",
		"di/core.go",
		"di/container_gen.go",
	} {
		content := readProjectFile(t, rel)
		for _, forbidden := range []string{legacyPrefix, legacySuffix + "Options"} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s still contains legacy option token %q", rel, forbidden)
			}
		}
	}
}

func TestNeutralizationEvidenceRecordsE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	cleanupRel := "process-term-neutralization-cleanup-2026-07-08.md"
	historyRel := "process-term-history-rewrite-map-2026-07-08.md"
	for _, rel := range []string{cleanupRel, historyRel} {
		runGit(t, evidenceRoot, "ls-files", "--error-unmatch", rel)
	}

	cleanup := readEvidenceFile(t, evidenceRoot, cleanupRel)
	legacyPrefix := "Clean" + "Room"
	legacySuffix := "Gap"
	for _, want := range []string{
		"Wicket cleanup commit after F3 rewrite",
		"Tool directories were not deleted",
		"BuilderExtensions/Core.cs#L261",
		"Renamed `" + legacyPrefix + "Key" + legacySuffix + "Options` to `KeyManagementOptions`.",
		"Renamed `" + legacyPrefix + "Provider" + legacySuffix + "Options` to `DynamicProviderOptions`.",
		"Renamed `" + legacyPrefix + "Session" + legacySuffix + "Options` to `ServerSideSessionOptions`.",
		"Renamed `WicketOptions." + legacyPrefix + "Provider" + legacySuffix + "` to `WicketOptions.DynamicProviders`.",
		"`PROVENANCE.md` evidence archive paths were replaced with a neutral availability statement.",
		"Both `rg` scans returned no matches",
	} {
		if !strings.Contains(cleanup, want) {
			t.Fatalf("%s missing %q", cleanupRel, want)
		}
	}

	history := readEvidenceFile(t, evidenceRoot, historyRel)
	if !strings.Contains(history, "git filter-branch --msg-filter") {
		t.Fatalf("%s missing rewrite tool record", historyRel)
	}
	for _, newMessage := range historyRewriteNewMessages(t, history) {
		assertNeutralProcessName(t, historyRel, newMessage)
	}
}

func trackedProjectPaths(t *testing.T) []string {
	t.Helper()

	output := runCommand(t, projectRoot(t), "git", "ls-files")
	return nonEmptyLines(output)
}

func testFunctionNames(t *testing.T, rel string) []string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(projectRoot(t), rel), nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}

	var names []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		names = append(names, fn.Name.Name)
	}
	return names
}

func historyRewriteNewMessages(t *testing.T, history string) []string {
	t.Helper()

	var messages []string
	for _, line := range strings.Split(history, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) < 5 {
			t.Fatalf("malformed history rewrite row: %s", line)
		}
		messages = append(messages, strings.Trim(strings.TrimSpace(columns[4]), "`"))
	}
	return messages
}

func assertNeutralProcessName(t *testing.T, subject string, value string) {
	t.Helper()

	for _, forbidden := range []string{
		"clean" + "-room",
		"Clean" + "Room",
		"buc" + "ket",
		"Buc" + "ket",
		"wicket-provenance-" + "evidence",
		"\u51c0\u5ba4",
		"\u6876 A",
		"\u6876 B",
		"\u6876 C",
	} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("%s contains non-neutral term %q in %q", subject, forbidden, value)
		}
	}

	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile("(?i)" + "story" + "[- ][0-9]"),
	} {
		if pattern.MatchString(value) {
			t.Fatalf("%s contains non-neutral pattern %q in %q", subject, pattern.String(), value)
		}
	}
}

func nonEmptyLines(output string) []string {
	lines := strings.Split(output, "\n")
	values := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			values = append(values, line)
		}
	}
	return values
}
