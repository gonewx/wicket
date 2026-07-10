package e2e_test

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testSplitLedgerFileName = "gois-full-file-provenance-ledger-2026-07-07.csv"
	testRoutingMatrixName   = "test-baseline-routing-matrix-2026-07-09.csv"
)

// pendingImplementationSkipReason is assembled rather than written whole so
// this guard does not match itself while scanning the tree.
var pendingImplementationSkipReason = "pending Epic " + "2/3 implementation"

func TestRegressionTestScopeE2E(t *testing.T) {
	t.Parallel()

	evidenceRoot := evidenceRepositoryRoot(t)
	rows := readTestSplitLedgerRows(t, filepath.Join(evidenceRoot, testSplitLedgerFileName))
	handledTests := readRoutingMatrixLandingPaths(t)

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

	// A landing path earns its exemption by carrying assertions, not by being
	// named: a file that still defers its behavior cannot stand for it.
	for rel := range handledTests {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("routing matrix landing path %s not present: %v", rel, err)
		}
		if strings.Contains(readProjectFile(t, rel), pendingImplementationSkipReason) {
			t.Fatalf("routing matrix landing path %s still defers its behavior", rel)
		}
	}

	for _, rel := range goFiles(t) {
		if !strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "tests/e2e/") {
			continue
		}
		if _, ok := handledTests[rel]; ok {
			continue
		}
		if disposition, ok := excludedLedgerTests[rel]; ok {
			t.Fatalf("non-Epic 1 ledger test %s is present with disposition %q", rel, disposition)
		}
	}
}

// disposedFinalStatuses are the routing-matrix outcomes under which a landing
// path may exempt a file from the presence guard. Blocked and archived rows
// carry no landing path, so naming one is itself a matrix defect.
var disposedFinalStatuses = map[string]struct{}{
	"migrated":          {},
	"already-restored":  {},
	"restored":          {},
	"rewritten":         {},
	"rewritten-partial": {},
	"covered-partial":   {},
}

// readRoutingMatrixLandingPaths collects the project-relative test paths the
// routing matrix records as carrying a disposed behavior set. It reads the
// synthesized final view (base matrix plus every append-only supplement), so a
// row a supplement disposes contributes its landing here just as an in-place
// edit would have. A path is only admitted when its row reports a disposed
// outcome, so neither an undisposed ledger test nor a landing claimed by a
// still-blocked row escapes the guard above.
func readRoutingMatrixLandingPaths(t *testing.T) map[string]struct{} {
	t.Helper()

	landings := map[string]struct{}{}
	for _, row := range synthesizedRoutingMatrix(t) {
		named := strings.Split(row.LandingPath, ";")
		if _, disposed := disposedFinalStatuses[row.FinalStatus]; !disposed {
			for _, landing := range named {
				if strings.TrimSpace(landing) != "" {
					t.Fatalf("routing matrix row %s names a landing path under undisposed status %q", row.GoisPath, row.FinalStatus)
				}
			}
			continue
		}
		rowLandings := 0
		for _, landing := range named {
			if landing = strings.TrimSpace(landing); landing != "" {
				landings[landing] = struct{}{}
				rowLandings++
			}
		}
		// A disposed row must point at the file carrying its behavior;
		// otherwise the disposition is an unbacked claim.
		if rowLandings == 0 {
			t.Fatalf("routing matrix row %s is disposed as %q but names no landing path", row.GoisPath, row.FinalStatus)
		}
	}
	if len(landings) == 0 {
		t.Fatal("routing matrix names no landing paths")
	}
	return landings
}

func readCsvRecords(t *testing.T, path string) [][]string {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", filepath.Base(path), err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	if len(records) == 0 {
		t.Fatalf("%s is empty", filepath.Base(path))
	}
	return records
}

func csvHeader(t *testing.T, path string, records [][]string) func(string) int {
	t.Helper()

	header := map[string]int{}
	for i, name := range records[0] {
		header[name] = i
	}
	return func(name string) int {
		t.Helper()
		index, ok := header[name]
		if !ok {
			t.Fatalf("%s missing %q column", filepath.Base(path), name)
		}
		return index
	}
}

func readTestSplitLedgerRows(t *testing.T, path string) []ledgerRow {
	t.Helper()

	records := readCsvRecords(t, path)
	column := csvHeader(t, path, records)

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

	skipCall := `t.Skip("` + pendingImplementationSkipReason + `")`

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
