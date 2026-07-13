package e2e_test

import (
	"bufio"
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

	manifestPaths := readMitManifestPaths(t, evidenceRoot)
	if len(manifestPaths) == 0 {
		t.Fatal("no MIT migration manifest files found in evidence repository")
	}

	mitHeaderFiles := scanMitHeaderFiles(t, projectRoot(t))

	for _, mp := range manifestPaths {
		fullPath := filepath.Join(projectRoot(t), mp)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			t.Fatalf("manifest declares %s but file does not exist in wicket", mp)
		}
		if !mitHeaderFiles[mp] {
			t.Fatalf("manifest declares %s but file does not carry MIT header", mp)
		}
	}

	for path := range mitHeaderFiles {
		found := false
		for _, mp := range manifestPaths {
			if mp == path {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("file %s carries MIT header but is not listed in any manifest", path)
		}
	}

	notice := readProjectFile(t, "NOTICE")
	if strings.Contains(notice, "identifies no") && strings.Contains(notice, "files migrated") {
		t.Fatal("NOTICE still contains the empty-declaration text after MIT files were migrated")
	}

	for _, required := range []string{
		"derived from the ASP.NET Core",
		"MIT License",
		"mit-migration-manifest-*.csv",
	} {
		if !strings.Contains(notice, required) {
			t.Fatalf("NOTICE missing required attribution text %q", required)
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

func readMitManifestPaths(t *testing.T, evidenceRoot string) []string {
	t.Helper()
	pattern := filepath.Join(evidenceRoot, "mit-migration-manifest-*.csv")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob manifest: %v", err)
	}
	var paths []string
	for _, match := range matches {
		f, err := os.Open(match)
		if err != nil {
			t.Fatalf("open manifest %s: %v", match, err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "wicket_path,") {
				continue
			}
			fields := strings.SplitN(line, ",", 2)
			if len(fields) > 0 && fields[0] != "" {
				paths = append(paths, fields[0])
			}
		}
		f.Close()
	}
	return paths
}

func scanMitHeaderFiles(t *testing.T, root string) map[string]bool {
	t.Helper()
	result := make(map[string]bool)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "_bmad-output" || base == ".claude" || base == ".codegraph" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		lineCount := 0
		for scanner.Scan() && lineCount < 5 {
			line := scanner.Text()
			if strings.Contains(line, ".NET Foundation and Contributors") &&
				strings.Contains(line, "Copyright") {
				rel, _ := filepath.Rel(root, path)
				result[rel] = true
				break
			}
			lineCount++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk project tree: %v", err)
	}
	return result
}
