package e2e_test

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSplitLedgerFileName = "gois-full-file-provenance-ledger-2026-07-07.csv"

func TestRegressionTestScopeE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	rows := readTestSplitLedgerRows(t, filepath.Join(evidenceRoot, testSplitLedgerFileName))

	testRows := 0
	dispositionCounts := map[string]int{}
	migratedTests := map[string]struct{}{}
	excludedLedgerTests := map[string]string{}
	for _, row := range rows {
		if row.Kind != "test" {
			continue
		}
		testRows++
		dispositionCounts[row.Disposition]++

		currentPath := currentApachePath(row.Path)
		switch row.Disposition {
		case "Epic 1 迁入":
			migratedTests[currentPath] = struct{}{}
		case "Epic 4 依行为契约重写", "不迁移+理由：godi/wicket 迁移过程专属测试，不是协议行为等价基线":
			excludedLedgerTests[currentPath] = row.Disposition
		default:
			t.Fatalf("test ledger row %q has unexpected disposition %q", row.Path, row.Disposition)
		}
	}

	if testRows != 144 {
		t.Fatalf("test ledger row count = %d, want 144", testRows)
	}
	if len(migratedTests) != 27 {
		t.Fatalf("migrated Epic 1 test path count = %d, want 27", len(migratedTests))
	}
	if dispositionCounts["Epic 1 迁入"] != 27 {
		t.Fatalf("Epic 1 migrated test count = %d, want 27", dispositionCounts["Epic 1 迁入"])
	}
	if dispositionCounts["Epic 4 依行为契约重写"] != 84 {
		t.Fatalf("Epic 4 behavior-contract rewrite test count = %d, want 84", dispositionCounts["Epic 4 依行为契约重写"])
	}
	if dispositionCounts["不迁移+理由：godi/wicket 迁移过程专属测试，不是协议行为等价基线"] != 33 {
		t.Fatalf("non-migrated gois migration test count = %d, want 33", dispositionCounts["不迁移+理由：godi/wicket 迁移过程专属测试，不是协议行为等价基线"])
	}

	root := projectRoot(t)
	for rel := range migratedTests {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("migrated Epic 1 test %s not present: %v", rel, err)
		}
	}

	for _, rel := range goFiles(t) {
		if !strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "tests/e2e/") {
			continue
		}
		if _, ok := restoredBehaviorTests[rel]; ok {
			continue
		}
		if disposition, ok := excludedLedgerTests[rel]; ok {
			t.Fatalf("non-Epic 1 ledger test %s is present with disposition %q", rel, disposition)
		}
	}
}

var restoredBehaviorTests = map[string]struct{}{
	"test/integration/handlers/authorize/resource_test.go": {},
	"validators/impl/resource_validator_test.go":           {},
}

func readTestSplitLedgerRows(t *testing.T, path string) []ledgerRow {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open test split ledger: %v", err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatalf("read test split ledger: %v", err)
	}
	if len(records) == 0 {
		t.Fatal("test split ledger is empty")
	}

	header := map[string]int{}
	for i, name := range records[0] {
		header[name] = i
	}
	column := func(name string) int {
		t.Helper()
		index, ok := header[name]
		if !ok {
			t.Fatalf("test split ledger missing %q column", name)
		}
		return index
	}

	pathIndex := column("path")
	kindIndex := column("kind")
	dispositionIndex := column("disposition")

	rows := make([]ledgerRow, 0, len(records)-1)
	for rowNo, record := range records[1:] {
		if len(record) <= pathIndex || len(record) <= kindIndex || len(record) <= dispositionIndex {
			t.Fatalf("test split ledger row %d has too few columns", rowNo+2)
		}
		rows = append(rows, ledgerRow{
			Path:        record[pathIndex],
			Kind:        record[kindIndex],
			Disposition: record[dispositionIndex],
		})
	}
	return rows
}

func TestPendingImplementationSkipDisciplineE2E(t *testing.T) {
	t.Parallel()

	skipReason := "pending Epic " + "2/3 implementation"
	skipCall := `t.Skip("` + skipReason + `")`

	for _, rel := range goFiles(t) {
		if !strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "tests/e2e/") {
			continue
		}

		content := readProjectFile(t, rel)
		for lineNo, line := range strings.Split(content, "\n") {
			if !strings.Contains(line, "pending Epic") && !strings.Contains(line, "implementation") {
				continue
			}
			if !strings.Contains(line, skipCall) {
				t.Fatalf("%s:%d has non-standard pending implementation skip line: %s", rel, lineNo+1, line)
			}
		}
	}
}
