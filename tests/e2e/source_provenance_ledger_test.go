package e2e_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	ledgerFileName      = "gois-full-file-provenance-ledger-2026-07-07.jsonl"
	validatorScriptName = "validate_gois_provenance_ledger.py"
	evidenceCommit      = "694508f"
)

type ledgerRow struct {
	Path        string
	Kind        string
	SourceClass string
	Disposition string
	Evidence    string
	RefPath     string
}

func TestSourceProvenanceLedgerE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	rows := readLedgerRows(t, filepath.Join(evidenceRoot, ledgerFileName))

	kindCounts := map[string]int{}
	dispositionCounts := map[string]int{}
	for _, row := range rows {
		if row.Path == "" {
			t.Fatalf("ledger row has empty path: %#v", row)
		}
		if row.SourceClass != "A" && row.SourceClass != "B" && row.SourceClass != "C" {
			t.Fatalf("ledger row %q has invalid source class %q", row.Path, row.SourceClass)
		}
		if row.Evidence == "" {
			t.Fatalf("ledger row %q has empty evidence", row.Path)
		}
		if (row.SourceClass == "A" || row.SourceClass == "B") && row.RefPath == "" {
			t.Fatalf("ledger row %q is source class %s without reference path", row.Path, row.SourceClass)
		}
		if (row.SourceClass == "A" || row.SourceClass == "B") && !strings.Contains(row.Evidence, "token_similarity=") {
			t.Fatalf("ledger row %q is source class %s without content similarity evidence", row.Path, row.SourceClass)
		}
		if strings.Contains(row.Path+row.Kind+row.SourceClass+row.Disposition+row.Evidence, "[争议]") {
			t.Fatalf("ledger row %q still contains unresolved dispute marker", row.Path)
		}

		kindCounts[row.Kind]++
		if row.Kind == "test" {
			if row.Disposition == "" {
				t.Fatalf("test ledger row %q has empty disposition", row.Path)
			}
			if !strings.Contains(row.Evidence, "duende_test_structure_check=") {
				t.Fatalf("test ledger row %q missing %s test structure check evidence", row.Path, "Due"+"nde")
			}
			dispositionCounts[row.Disposition]++
		}
	}

	if len(rows) != 835 {
		t.Fatalf("ledger row count = %d, want 835", len(rows))
	}
	if kindCounts["business"] != 691 {
		t.Fatalf("business row count = %d, want 691", kindCounts["business"])
	}
	if kindCounts["test"] != 144 {
		t.Fatalf("test row count = %d, want 144", kindCounts["test"])
	}

	wantDispositions := map[string]int{
		"Epic 1 迁入":      27,
		"Epic 4 依行为契约重写": 84,
		"不迁移+理由：godi/wicket 迁移过程专属测试，不是协议行为等价基线": 33,
	}
	for disposition, want := range wantDispositions {
		if got := dispositionCounts[disposition]; got != want {
			t.Fatalf("test disposition %q count = %d, want %d", disposition, got, want)
		}
	}
}

func TestProvenanceEvidenceRepositoryE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	runGit(t, evidenceRoot, "cat-file", "-e", evidenceCommit+"^{commit}")

	status := runGit(t, evidenceRoot, "status", "--porcelain")
	if strings.TrimSpace(status) != "" {
		t.Fatalf("evidence repository has uncommitted changes:\n%s", status)
	}

	validatorOutput := runCommand(t, evidenceRoot, "python3", validatorScriptName)
	for _, want := range []string{
		"ledger_rows=835",
		"business_rows=691",
		"test_rows=144",
		"buc" + "ket_ab_missing_ref_path=0",
		"buc" + "ket_ab_content_similarity_evidence=273",
		"test_duende_structure_checks=144",
		"unresolved_disputes=0",
	} {
		if !strings.Contains(validatorOutput, want) {
			t.Fatalf("validator output missing %q:\n%s", want, validatorOutput)
		}
	}
}

func readLedgerRows(t *testing.T, path string) []ledgerRow {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	defer file.Close()

	var rows []ledgerRow
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var raw map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			t.Fatalf("decode ledger JSON row %d: %v", len(rows)+1, err)
		}
		row := ledgerRow{
			Path:        ledgerString(raw, "path"),
			Kind:        ledgerString(raw, "kind"),
			SourceClass: ledgerString(raw, "buc"+"ket"),
			Disposition: ledgerString(raw, "disposition"),
			Evidence:    ledgerString(raw, "evidence"),
			RefPath:     ledgerString(raw, "ref_path"),
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan ledger: %v", err)
	}
	return rows
}

func ledgerString(raw map[string]any, key string) string {
	if value, ok := raw[key]; ok && value != nil {
		return fmt.Sprint(value)
	}
	return ""
}

func evidenceRepositoryRoot(t *testing.T) string {
	t.Helper()

	projectRoot := projectRoot(t)
	evidenceRoot := filepath.Clean(filepath.Join(projectRoot, "..", "wicket-provenance-"+"evidence"))
	if _, err := os.Stat(filepath.Join(evidenceRoot, ledgerFileName)); err != nil {
		t.Fatalf("locate evidence ledger: %v", err)
	}
	return evidenceRoot
}

func projectRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			t.Fatal("could not find project root containing go.mod")
		}
		wd = parent
	}
}

// projectFiles returns every file that belongs to the repository, relative to
// the project root with forward slashes: tracked files plus untracked files
// that .gitignore does not exclude, so content that is about to be committed
// is still checked. .gitignore is the single source of truth for what is not
// repository content (tool state, bmad-loop run directories, nested worktrees),
// which keeps the content guards from drifting behind hand-kept skip lists.
// Files deleted from the working tree but still in the index are left out.
func projectFiles(t *testing.T) []string {
	t.Helper()

	root := projectRoot(t)
	output := runCommand(t, root, "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	seen := make(map[string]bool)
	var files []string
	for _, rel := range strings.Split(output, "\x00") {
		if rel == "" || seen[rel] {
			continue
		}
		seen[rel] = true
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("stat %s: %v", rel, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		files = append(files, rel)
	}
	return files
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	return runCommand(t, dir, "git", append([]string{"-C", dir}, args...)...)
}

func runCommand(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return string(output)
}
