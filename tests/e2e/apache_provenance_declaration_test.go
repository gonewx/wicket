package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApacheProvenanceDeclarationE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	rows := readLedgerRows(t, filepath.Join(evidenceRoot, ledgerFileName))

	apacheRefs := map[string]string{}
	business := 0
	testFiles := 0
	for _, row := range rows {
		if row.SourceClass != "B" {
			continue
		}
		apacheRefs[currentApachePath(row.Path)] = row.RefPath
		switch row.Kind {
		case "business":
			business++
		case "test":
			testFiles++
		}
	}
	if len(apacheRefs) != 273 {
		t.Fatalf("Apache-origin row count = %d, want 273", len(apacheRefs))
	}
	if business != 246 {
		t.Fatalf("Apache-origin business row count = %d, want 246", business)
	}
	if testFiles != 27 {
		t.Fatalf("Apache-origin test row count = %d, want 27", testFiles)
	}

	provenance := readProjectFile(t, "PROVENANCE.md")
	for _, want := range []string{
		"IdentityServer4 Apache reference: tag `4.1.1`",
		"Brock Allen & Dominick Baier",
		"gonewx/gois main@5d5f97c",
		"Evidence ledger commit: `694508f`",
		"Apache-origin rows copied: `273`",
		"Business files: `246`",
		"Epic 1 migrated tests: `27`",
		"Method-level review records and increment handoff records are maintained in the project's evidence archive",
	} {
		if !strings.Contains(provenance, want) {
			t.Fatalf("PROVENANCE.md missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"Due" + "ndeSoftware",
		"Due" + "nde 6." + "1.4",
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

	for rel := range apacheRefs {
		if _, err := os.Stat(filepath.Join(projectRoot(t), rel)); err != nil {
			t.Fatalf("Apache-origin path %s not present: %v", rel, err)
		}
	}
}

func TestApacheFromCommentsAndForbiddenCodeE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	rows := readLedgerRows(t, filepath.Join(evidenceRoot, ledgerFileName))
	apacheRefs := map[string]string{}
	for _, row := range rows {
		if row.SourceClass == "B" {
			apacheRefs[currentApachePath(row.Path)] = row.RefPath
		}
	}

	for _, rel := range goFiles(t) {
		if _, ok := apacheRefs[rel]; !ok {
			continue
		}
		content := readProjectFile(t, rel)
		for lineNo, line := range strings.Split(content, "\n") {
			if !strings.HasPrefix(line, "// From:") {
				continue
			}
			if strings.Contains(line, "Due"+"nde") || strings.Contains(line, "6."+"1.4") || strings.Contains(line, "Due"+"ndeSoftware") {
				t.Fatalf("%s:%d contains forbidden From provenance: %s", rel, lineNo+1, line)
			}
			wantRef, ok := apacheRefs[rel]
			if !ok {
				t.Fatalf("%s:%d has From comment outside Apache-origin ledger: %s", rel, lineNo+1, line)
			}
			want := "// From: IdentityServer4/" + wantRef
			if line != want {
				t.Fatalf("%s:%d From comment = %q, want %q", rel, lineNo+1, line, want)
			}
		}

		for _, forbidden := range []string{
			"Due" + "ndeSoftware",
			"Due" + "nde Software",
			"LicenseValidator",
			"ValidateResourceIndicators",
			"ResourceIndicator",
		} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s contains forbidden independent subsystem/v5+ token %q", rel, forbidden)
			}
		}
	}
}

func TestApacheScopeExcludesIndependentSubsystemsE2E(t *testing.T) {
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
		"validators/resource_validator.go",
	} {
		if _, err := os.Stat(filepath.Join(projectRoot(t), rel)); err == nil {
			t.Fatalf("independent subsystem subsystem path was copied: %s", rel)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", rel, err)
		}
	}
}

func TestApacheEvidenceReportsE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	for _, rel := range []string{
		"risk-acceptance-5.5-item3-item4.md",
		"buc" + "ket-b-method-diff-review-2026-07-07.md",
		"buc" + "ket-c-increment-handoff-2026-07-07.md",
	} {
		if _, err := os.Stat(filepath.Join(evidenceRoot, rel)); err != nil {
			t.Fatalf("evidence file %s missing: %v", rel, err)
		}
	}
}

func goFiles(t *testing.T) []string {
	t.Helper()

	var files []string
	for _, rel := range projectFiles(t) {
		if strings.HasSuffix(rel, ".go") {
			files = append(files, rel)
		}
	}
	return files
}

func currentApachePath(ledgerPath string) string {
	switch ledgerPath {
	case "config/options/identity_server_options.go":
		return "config/options/wicket_options.go"
	case "config/options/mock/test_identity_server_options.go":
		return "config/options/mock/test_wicket_options.go"
	case "models/identity_server_user.go":
		return "models/local_user.go"
	case "test/integration/common/identity_server_pipeline.go":
		return "test/integration/common/wicket_pipeline.go"
	case "tools/identity_server_tools.go":
		return "tools/token_tools.go"
	case "di/core.go":
		return "di/dsl_core.go"
	case "di/crypto.go":
		return "di/dsl_crypto.go"
	case "di/additional.go":
		return "di/dsl_additional.go"
	case "di/message_cookie.go":
		return "di/dsl_message_cookie.go"
	default:
		return ledgerPath
	}
}
