package e2e_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// routingMatrixSupplementGlob matches the append-only supplement files that
// dispose blocked base-matrix rows one story at a time. The 2026-07-09 base
// matrix is never rewritten; each story records its transitions in a
// supplement instead, and the disposition guards read the base and every
// supplement folded together.
const routingMatrixSupplementGlob = "test-baseline-routing-matrix-supplement-*.csv"

// blockedFinalStatuses are the base-matrix outcomes a supplement row may
// transition away from. A supplement may only act on a row still awaiting a
// later story; it can never re-open a row that is already disposed, archived,
// or without extractable behavior.
var blockedFinalStatuses = map[string]struct{}{
	"blocked-rewrite":     {},
	"blocked-backfill":    {},
	"rolled-back-blocked": {},
}

// routingMatrixRow is one row of the synthesized final view: a base-matrix row
// after every applicable supplement override has been folded in.
type routingMatrixRow struct {
	GoisPath    string
	WicketPath  string
	FinalStatus string
	LandingPath string
}

// synthesizedRoutingMatrix reads the base matrix and folds every supplement
// override into it, returning the final view both disposition guards consume.
// Each override is validated as it is applied: it must name a base row, that
// row must still be blocked, and the transition must land in a disposed status
// carrying a non-empty landing path. Any violation fails the test closed, so a
// supplement can only ever tighten a blocked row into a backed disposition —
// never loosen a guarantee the base matrix already makes, and never re-dispose
// a row an earlier supplement already moved (its status is no longer blocked).
func synthesizedRoutingMatrix(t *testing.T) []routingMatrixRow {
	t.Helper()

	evidenceRoot := evidenceRepositoryRoot(t)
	matrixPath := filepath.Join(evidenceRoot, testRoutingMatrixName)
	records := readCsvRecords(t, matrixPath)
	header := csvHeader(t, matrixPath, records)
	goisIndex := header("gois_path")
	pathIndex := header("wicket_path")
	statusIndex := header("final_status")
	landingIndex := header("wicket_landing_path")

	rows := make([]routingMatrixRow, 0, len(records)-1)
	byGois := map[string]int{}
	for rowNo, record := range records[1:] {
		if len(record) <= goisIndex || len(record) <= pathIndex ||
			len(record) <= statusIndex || len(record) <= landingIndex {
			t.Fatalf("routing matrix row %d has too few columns", rowNo+2)
		}
		gois := strings.TrimSpace(record[goisIndex])
		if _, dup := byGois[gois]; dup {
			t.Fatalf("routing matrix has duplicate gois_path %q", gois)
		}
		byGois[gois] = len(rows)
		rows = append(rows, routingMatrixRow{
			GoisPath:    gois,
			WicketPath:  strings.TrimSpace(record[pathIndex]),
			FinalStatus: strings.TrimSpace(record[statusIndex]),
			LandingPath: strings.TrimSpace(record[landingIndex]),
		})
	}

	for _, supplement := range routingMatrixSupplementFiles(t, evidenceRoot) {
		applyRoutingMatrixSupplement(t, supplement, rows, byGois)
	}
	return rows
}

// routingMatrixSupplementFiles returns the supplement CSVs in deterministic
// order so overrides fold in reproducibly regardless of directory listing.
func routingMatrixSupplementFiles(t *testing.T, evidenceRoot string) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(evidenceRoot, routingMatrixSupplementGlob))
	if err != nil {
		t.Fatalf("glob routing matrix supplements: %v", err)
	}
	sort.Strings(matches)
	return matches
}

// applyRoutingMatrixSupplement folds one supplement file into rows, enforcing
// the legality of every override before it takes effect.
func applyRoutingMatrixSupplement(t *testing.T, path string, rows []routingMatrixRow, byGois map[string]int) {
	t.Helper()

	records := readCsvRecords(t, path)
	header := csvHeader(t, path, records)
	goisIndex := header("gois_path")
	statusIndex := header("final_status")
	landingIndex := header("wicket_landing_path")

	base := filepath.Base(path)
	for rowNo, record := range records[1:] {
		if len(record) <= goisIndex || len(record) <= statusIndex || len(record) <= landingIndex {
			t.Fatalf("%s row %d has too few columns", base, rowNo+2)
		}
		gois := strings.TrimSpace(record[goisIndex])
		idx, ok := byGois[gois]
		if !ok {
			t.Fatalf("%s row %d overrides unknown gois_path %q", base, rowNo+2, gois)
		}
		if _, blocked := blockedFinalStatuses[rows[idx].FinalStatus]; !blocked {
			t.Fatalf("%s row %d overrides gois_path %q whose current status %q is not blocked", base, rowNo+2, gois, rows[idx].FinalStatus)
		}
		status := strings.TrimSpace(record[statusIndex])
		if _, disposed := disposedFinalStatuses[status]; !disposed {
			t.Fatalf("%s row %d transitions gois_path %q to non-disposed status %q", base, rowNo+2, gois, status)
		}
		landing := strings.TrimSpace(record[landingIndex])
		if landing == "" || landing == "-" {
			t.Fatalf("%s row %d disposes gois_path %q but names no landing path", base, rowNo+2, gois)
		}
		rows[idx].FinalStatus = status
		rows[idx].LandingPath = landing
	}
}
