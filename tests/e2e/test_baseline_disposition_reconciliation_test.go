package e2e_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// knownFinalStatuses enumerates every outcome the routing matrix may record.
// Disposed statuses admit landing paths (see disposedFinalStatuses); the
// remainder describe rows that either keep their skip stub, were archived, or
// yielded no extractable behavior.
var knownFinalStatuses = map[string]struct{}{
	"migrated":                {},
	"already-restored":        {},
	"restored":                {},
	"rewritten":               {},
	"rewritten-partial":       {},
	"covered-partial":         {},
	"no-extractable-behavior": {},
	"archived":                {},
	"blocked-rewrite":         {},
	"blocked-backfill":        {},
	"rolled-back-blocked":     {},
}

// blockedStubStatuses are the outcomes whose wicket file must remain a skip
// stub until a later story resolves its missing dependency.
var blockedStubStatuses = map[string]struct{}{
	"blocked-backfill":    {},
	"rolled-back-blocked": {},
}

// TestBaselineDispositionReconciliationE2E holds the routing matrix and the
// working tree to the same story: every matrix row carries a known outcome,
// every stub-blocked row (blocked-backfill, rolled-back-blocked) still has its
// skip stub in place, and every skip stub in the tree is claimed by exactly
// one such row. blocked-rewrite rows never had a stub to reconcile; their
// premature landing is caught by the ledger presence guard instead. A stub
// deleted without a matrix correction, or a stub half-restored while its row
// stays blocked, breaks the reconciliation either way.
func TestBaselineDispositionReconciliationE2E(t *testing.T) {
	t.Parallel()

	for status := range disposedFinalStatuses {
		if _, ok := knownFinalStatuses[status]; !ok {
			t.Fatalf("disposed status %q missing from knownFinalStatuses", status)
		}
	}
	for status := range blockedStubStatuses {
		if _, ok := knownFinalStatuses[status]; !ok {
			t.Fatalf("blocked stub status %q missing from knownFinalStatuses", status)
		}
	}

	matrixPath := filepath.Join(evidenceRepositoryRoot(t), testRoutingMatrixName)
	records := readCsvRecords(t, matrixPath)
	header := csvHeader(t, matrixPath, records)
	pathIndex := header("wicket_path")
	statusIndex := header("final_status")

	blockedStubs := map[string]struct{}{}
	for rowNo, record := range records[1:] {
		if len(record) <= pathIndex || len(record) <= statusIndex {
			t.Fatalf("routing matrix row %d has too few columns", rowNo+2)
		}
		status := strings.TrimSpace(record[statusIndex])
		if _, ok := knownFinalStatuses[status]; !ok {
			t.Fatalf("routing matrix row %d has unknown final_status %q", rowNo+2, status)
		}
		if _, blocked := blockedStubStatuses[status]; !blocked {
			continue
		}
		rel := strings.TrimSpace(record[pathIndex])
		if rel == "" || rel == "-" {
			t.Fatalf("routing matrix row %d is blocked but names no wicket path", rowNo+2)
		}
		if _, dup := blockedStubs[rel]; dup {
			t.Fatalf("wicket path %s is claimed by more than one blocked matrix row", rel)
		}
		blockedStubs[rel] = struct{}{}
	}

	if rowCount := len(records) - 1; rowCount != 144 {
		t.Fatalf("routing matrix row count = %d, want 144", rowCount)
	}

	stubFiles := map[string]struct{}{}
	for _, rel := range goFiles(t) {
		if !strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "tests/e2e/") {
			continue
		}
		if strings.Contains(readProjectFile(t, rel), pendingImplementationSkipReason) {
			stubFiles[rel] = struct{}{}
		}
	}

	for rel := range blockedStubs {
		if _, ok := stubFiles[rel]; !ok {
			t.Fatalf("blocked matrix row %s no longer carries its skip stub", rel)
		}
	}
	for rel := range stubFiles {
		if _, ok := blockedStubs[rel]; !ok {
			t.Fatalf("skip stub %s is not claimed by any blocked matrix row", rel)
		}
	}
}
