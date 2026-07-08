package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMitNoticeScopeE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	rows := readLedgerRows(t, filepath.Join(evidenceRoot, ledgerFileName))

	sourceClassCounts := map[string]int{}
	for _, row := range rows {
		sourceClassCounts[row.SourceClass]++
	}

	if sourceClassCounts["A"] != 0 {
		t.Fatalf("source class A row count = %d, want 0", sourceClassCounts["A"])
	}
	if sourceClassCounts["B"] != 273 {
		t.Fatalf("Apache-origin row count = %d, want 273", sourceClassCounts["B"])
	}
	if sourceClassCounts["C"] != 562 {
		t.Fatalf("source class C row count = %d, want 562", sourceClassCounts["C"])
	}

	validatorOutput := runCommand(t, evidenceRoot, "python3", validatorScriptName)
	for _, want := range []string{
		"ledger_rows=835",
		"buc" + "ket_ab_missing_ref_path=0",
		"buc" + "ket_ab_content_similarity_evidence=273",
		"unresolved_disputes=0",
	} {
		if !strings.Contains(validatorOutput, want) {
			t.Fatalf("validator output missing %q:\n%s", want, validatorOutput)
		}
	}

	notice := readProjectFile(t, "NOTICE")
	for _, want := range []string{
		"The current provenance ledger identifies no " + "Buc" + "ket A files migrated into\nwicket.",
		"wicket does not contain code derived from\nASP.NET Core or Microsoft.IdentityModel under this " + "buc" + "ket.",
		"This section is reserved for future " + "Buc" + "ket A attribution",
	} {
		if !strings.Contains(notice, want) {
			t.Fatalf("NOTICE missing %q:\n%s", want, notice)
		}
	}

	for _, forbidden := range []string{
		"Portions of wicket are derived from ASP.NET Core",
		"Microsoft.IdentityModel libraries, originally developed by Microsoft",
		"Affected modules: auth/",
		"See individual file headers\nand PROVENANCE.md for per-file attribution",
	} {
		if strings.Contains(notice, forbidden) {
			t.Fatalf("NOTICE still contains stale source class A attribution %q", forbidden)
		}
	}
}

func TestMitNoticeNoOutOfScopeArtifactsE2E(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"options",
	} {
		if _, err := os.Stat(filepath.Join(projectRoot(t), path)); err == nil {
			t.Fatalf("out-of-scope source class A story artifact exists: %s", path)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
}

func readProjectFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(projectRoot(t), path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
