package e2e_test

import (
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
// stub until a later change resolves its missing dependency.
var blockedStubStatuses = map[string]struct{}{
	"blocked-backfill":    {},
	"rolled-back-blocked": {},
}

// TestBaselineDispositionReconciliationE2E holds the routing matrix and the
// working tree in lockstep: every matrix row carries a known outcome,
// every stub-blocked row (blocked-backfill, rolled-back-blocked) still has its
// skip stub in place, and every skip stub in the tree is claimed by exactly
// one such row. blocked-rewrite rows never had a stub to reconcile; their
// premature landing is caught by the ledger presence guard instead. A stub
// deleted without a matrix correction, or a stub half-restored while its row
// stays blocked, breaks the reconciliation either way.
//
// The matrix is read as the synthesized final view — base matrix plus every
// append-only supplement — so a supplement that disposes a blocked row records its
// transition separately rather than rewriting the 2026-07-09 base. A row
// a supplement moves out of a blocked status is no longer expected to keep a
// stub, exactly as an in-place edit would have required.
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

	rows := synthesizedRoutingMatrix(t)

	blockedStubs := map[string]struct{}{}
	for _, row := range rows {
		if _, ok := knownFinalStatuses[row.FinalStatus]; !ok {
			t.Fatalf("routing matrix row %s has unknown final_status %q", row.GoisPath, row.FinalStatus)
		}
		if _, blocked := blockedStubStatuses[row.FinalStatus]; !blocked {
			continue
		}
		rel := row.WicketPath
		if rel == "" || rel == "-" {
			t.Fatalf("routing matrix row %s is blocked but names no wicket path", row.GoisPath)
		}
		if _, dup := blockedStubs[rel]; dup {
			t.Fatalf("wicket path %s is claimed by more than one blocked matrix row", rel)
		}
		blockedStubs[rel] = struct{}{}
	}

	if rowCount := len(rows); rowCount != 144 {
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
