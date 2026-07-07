package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBucketAEmptyMigrationAndNoticeE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	rows := readLedgerRows(t, filepath.Join(evidenceRoot, ledgerFileName))

	bucketCounts := map[string]int{}
	for _, row := range rows {
		bucketCounts[row.Bucket]++
	}

	if bucketCounts["A"] != 0 {
		t.Fatalf("bucket A row count = %d, want 0", bucketCounts["A"])
	}
	if bucketCounts["B"] != 273 {
		t.Fatalf("bucket B row count = %d, want 273", bucketCounts["B"])
	}
	if bucketCounts["C"] != 562 {
		t.Fatalf("bucket C row count = %d, want 562", bucketCounts["C"])
	}

	validatorOutput := runCommand(t, evidenceRoot, "python3", validatorScriptName)
	for _, want := range []string{
		"ledger_rows=835",
		"bucket_ab_missing_ref_path=0",
		"bucket_ab_content_similarity_evidence=273",
		"unresolved_disputes=0",
	} {
		if !strings.Contains(validatorOutput, want) {
			t.Fatalf("validator output missing %q:\n%s", want, validatorOutput)
		}
	}

	notice := readProjectFile(t, "NOTICE")
	for _, want := range []string{
		"The current provenance ledger identifies no Bucket A files migrated into\nwicket.",
		"wicket does not contain code derived from\nASP.NET Core or Microsoft.IdentityModel under this bucket.",
		"This section is reserved for future Bucket A attribution",
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
			t.Fatalf("NOTICE still contains stale Bucket A attribution %q", forbidden)
		}
	}
}

func TestBucketAStoryCreatedNoOutOfScopeArtifactsE2E(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"auth",
		"options",
		"PROVENANCE.md",
	} {
		if _, err := os.Stat(filepath.Join(projectRoot(t), path)); err == nil {
			t.Fatalf("out-of-scope Bucket A story artifact exists: %s", path)
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
