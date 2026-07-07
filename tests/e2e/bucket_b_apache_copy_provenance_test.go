package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBucketBApacheCopyProvenanceE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	rows := readLedgerRows(t, filepath.Join(evidenceRoot, ledgerFileName))

	bucketBRefs := map[string]string{}
	business := 0
	testFiles := 0
	for _, row := range rows {
		if row.Bucket != "B" {
			continue
		}
		bucketBRefs[row.Path] = row.RefPath
		switch row.Kind {
		case "business":
			business++
		case "test":
			testFiles++
		}
	}
	if len(bucketBRefs) != 273 {
		t.Fatalf("bucket B row count = %d, want 273", len(bucketBRefs))
	}
	if business != 246 {
		t.Fatalf("bucket B business row count = %d, want 246", business)
	}
	if testFiles != 27 {
		t.Fatalf("bucket B test row count = %d, want 27", testFiles)
	}

	provenance := readProjectFile(t, "PROVENANCE.md")
	for _, want := range []string{
		"IdentityServer4 Apache reference: tag `4.1.1`",
		"Brock Allen & Dominick Baier",
		"gonewx/gois main@5d5f97c",
		"Evidence ledger commit: `694508f`",
		"Bucket B rows copied: `273`",
		"Business files: `246`",
		"Epic 1 migrated tests: `27`",
		"bucket-b-method-diff-review-2026-07-07.md",
		"bucket-c-increment-handoff-2026-07-07.md",
	} {
		if !strings.Contains(provenance, want) {
			t.Fatalf("PROVENANCE.md missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"DuendeSoftware",
		"Duende 6.1.4",
		"LicenseValidator",
		"ValidateResourceIndicators",
	} {
		if strings.Contains(provenance, forbidden) {
			t.Fatalf("PROVENANCE.md contains forbidden text %q", forbidden)
		}
	}

	notice := readProjectFile(t, "NOTICE")
	if !strings.Contains(notice, "See PROVENANCE.md") {
		t.Fatalf("NOTICE does not reference PROVENANCE.md")
	}

	for rel := range bucketBRefs {
		if _, err := os.Stat(filepath.Join(projectRoot(t), rel)); err != nil {
			t.Fatalf("bucket B path %s not present: %v", rel, err)
		}
	}
}

func TestBucketBFromCommentsAndForbiddenCodeE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	rows := readLedgerRows(t, filepath.Join(evidenceRoot, ledgerFileName))
	bucketBRefs := map[string]string{}
	for _, row := range rows {
		if row.Bucket == "B" {
			bucketBRefs[row.Path] = row.RefPath
		}
	}

	for _, rel := range goFiles(t) {
		if _, ok := bucketBRefs[rel]; !ok {
			continue
		}
		content := readProjectFile(t, rel)
		for lineNo, line := range strings.Split(content, "\n") {
			if !strings.HasPrefix(line, "// From:") {
				continue
			}
			if strings.Contains(line, "Duende") || strings.Contains(line, "6.1.4") || strings.Contains(line, "DuendeSoftware") {
				t.Fatalf("%s:%d contains forbidden From provenance: %s", rel, lineNo+1, line)
			}
			wantRef, ok := bucketBRefs[rel]
			if !ok {
				t.Fatalf("%s:%d has From comment outside Bucket B ledger: %s", rel, lineNo+1, line)
			}
			want := "// From: IdentityServer4/" + wantRef
			if line != want {
				t.Fatalf("%s:%d From comment = %q, want %q", rel, lineNo+1, line, want)
			}
		}

		for _, forbidden := range []string{
			"DuendeSoftware",
			"Duende Software",
			"LicenseValidator",
			"ValidateResourceIndicators",
			"BackchannelAuthentication",
			"backchannel authentication request",
			"CIBA",
			"Ciba",
			"KeyManagement",
			"DynamicProvider",
			"ServerSideSession",
			"ResourceIndicator",
		} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s contains forbidden Bucket C/v5+ token %q", rel, forbidden)
			}
		}
	}
}

func TestBucketBDoesNotCopyBucketCSubsystemsE2E(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{
		"services/impl/key_manager.go",
		"services/impl/key_material_service.go",
		"services/impl/automatic_key_manager_storage.go",
		"services/impl/data_protection_key_protector.go",
		"services/impl/file_system_key_storage.go",
		"services/impl/memory_key_storage_cache.go",
		"services/impl/user_session.go",
		"services/impl/server_urls.go",
		"validators/impl/resource_validator.go",
		"validators/resource_validator.go",
	} {
		if _, err := os.Stat(filepath.Join(projectRoot(t), rel)); err == nil {
			t.Fatalf("Bucket C subsystem path was copied: %s", rel)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", rel, err)
		}
	}
}

func TestBucketBEvidenceReportsE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	for _, rel := range []string{
		"risk-acceptance-5.5-item3-item4.md",
		"bucket-b-method-diff-review-2026-07-07.md",
		"bucket-c-increment-handoff-2026-07-07.md",
	} {
		if _, err := os.Stat(filepath.Join(evidenceRoot, rel)); err != nil {
			t.Fatalf("evidence file %s missing: %v", rel, err)
		}
	}
}

func goFiles(t *testing.T) []string {
	t.Helper()

	var files []string
	err := filepath.WalkDir(projectRoot(t), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", ".agents", ".rnix":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			rel, err := filepath.Rel(projectRoot(t), path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk project Go files: %v", err)
	}
	return files
}
