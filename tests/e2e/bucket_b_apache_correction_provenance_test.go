package e2e_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBucketBProvenanceTableMatchesCorrectionLedgerE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	rows := readLedgerRows(t, filepath.Join(evidenceRoot, ledgerFileName))
	provenanceRows := parseBucketBProvenanceRows(t, readProjectFile(t, "PROVENANCE.md"))

	bucketBRows := 0
	for _, row := range rows {
		if row.Bucket != "B" {
			continue
		}
		bucketBRows++

		currentPath := currentBucketBPath(row.Path)
		got, ok := provenanceRows[currentPath]
		if !ok {
			t.Fatalf("PROVENANCE.md missing bucket B current path %s for ledger path %s", currentPath, row.Path)
		}
		if got.kind != row.Kind {
			t.Fatalf("PROVENANCE.md kind for %s = %q, want %q", row.Path, got.kind, row.Kind)
		}

		wantGoisSource := fmt.Sprintf("gonewx/gois@5d5f97c:%s", row.Path)
		if got.goisSource != wantGoisSource {
			t.Fatalf("PROVENANCE.md gois source for %s = %q, want %q", row.Path, got.goisSource, wantGoisSource)
		}

		wantRef := "IdentityServer4/" + row.RefPath
		if got.identityServerRef != wantRef {
			t.Fatalf("PROVENANCE.md IS4 ref for %s = %q, want %q", row.Path, got.identityServerRef, wantRef)
		}

		if !strings.Contains(got.reviewConclusion, "Bucket B Apache-era lineage confirmed") &&
			!strings.Contains(got.reviewConclusion, "neutral clean-room placeholder") {
			t.Fatalf("PROVENANCE.md review conclusion for %s is not an accepted Story 1.3 correction outcome: %q", row.Path, got.reviewConclusion)
		}
	}

	if bucketBRows != 273 {
		t.Fatalf("bucket B ledger rows = %d, want 273", bucketBRows)
	}
	if len(provenanceRows) != bucketBRows {
		t.Fatalf("PROVENANCE.md migrated rows = %d, want %d", len(provenanceRows), bucketBRows)
	}
}

func TestBucketBCorrectionEvidenceChainE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	for _, commit := range []string{"9503eaf", "ef7d268"} {
		runGit(t, evidenceRoot, "cat-file", "-e", commit+"^{commit}")
	}

	for _, rel := range []string{
		"risk-acceptance-5.5-item3-item4.md",
		"bucket-b-method-diff-review-2026-07-07.md",
		"bucket-c-increment-handoff-2026-07-07.md",
	} {
		runGit(t, evidenceRoot, "ls-files", "--error-unmatch", rel)
	}

	riskAcceptance := readEvidenceFile(t, evidenceRoot, "risk-acceptance-5.5-item3-item4.md")
	for _, want := range []string{
		"Story 1.3",
		"// From:",
		"Decker",
		"20260707",
	} {
		if !strings.Contains(riskAcceptance, want) {
			t.Fatalf("risk acceptance evidence missing %q", want)
		}
	}

	methodReview := readEvidenceFile(t, evidenceRoot, "bucket-b-method-diff-review-2026-07-07.md")
	for _, want := range []string{
		"gois source: `gonewx/gois main@5d5f97c`",
		"IS4 Apache tag: `4.1.1`",
		"Duende comparison tag: `6.1.4`",
		"risk acceptance commit: `9503eaf`",
	} {
		if !strings.Contains(methodReview, want) {
			t.Fatalf("method review evidence missing %q", want)
		}
	}

	handoff := readEvidenceFile(t, evidenceRoot, "bucket-c-increment-handoff-2026-07-07.md")
	for _, want := range []string{
		"risk acceptance commit: `9503eaf`",
		"validators/impl/resource_validator.go",
		"services/impl/user_session.go",
		"neutral clean-room placeholder",
	} {
		if !strings.Contains(handoff, want) {
			t.Fatalf("Bucket C handoff evidence missing %q", want)
		}
	}
}

func TestBucketBNoticeProvenanceReferenceResolvesE2E(t *testing.T) {
	t.Parallel()

	notice := readProjectFile(t, "NOTICE")
	const provenancePath = "PROVENANCE.md"
	if !strings.Contains(notice, "See "+provenancePath) {
		t.Fatalf("NOTICE does not reference %s", provenancePath)
	}
	if _, err := os.Stat(filepath.Join(projectRoot(t), provenancePath)); err != nil {
		t.Fatalf("NOTICE references %s, but it does not resolve: %v", provenancePath, err)
	}
}

type bucketBProvenanceRow struct {
	kind              string
	goisSource        string
	identityServerRef string
	reviewConclusion  string
}

func parseBucketBProvenanceRows(t *testing.T, provenance string) map[string]bucketBProvenanceRow {
	t.Helper()

	rows := map[string]bucketBProvenanceRow{}
	for _, line := range strings.Split(provenance, "\n") {
		if !strings.HasPrefix(line, "| `") || !strings.Contains(line, "gonewx/gois@5d5f97c:") {
			continue
		}

		columns := strings.Split(line, "|")
		if len(columns) < 7 {
			t.Fatalf("malformed PROVENANCE.md migrated file row: %s", line)
		}

		path := markdownTableCode(columns[1])
		if path == "" {
			t.Fatalf("PROVENANCE.md migrated file row has empty path: %s", line)
		}
		if _, exists := rows[path]; exists {
			t.Fatalf("PROVENANCE.md has duplicate migrated file row for %s", path)
		}

		rows[path] = bucketBProvenanceRow{
			kind:              strings.TrimSpace(columns[2]),
			goisSource:        markdownTableCode(columns[3]),
			identityServerRef: markdownTableCode(columns[4]),
			reviewConclusion:  strings.TrimSpace(columns[5]),
		}
	}
	return rows
}

func markdownTableCode(column string) string {
	return strings.Trim(strings.TrimSpace(column), "`")
}

func readEvidenceFile(t *testing.T, root string, rel string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read evidence file %s: %v", rel, err)
	}
	return string(content)
}
