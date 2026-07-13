package e2e_test

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// routingMatrixSupplementGlob matches the append-only supplement files that
// dispose blocked base-matrix rows one at a time. The 2026-07-09 base
// matrix is never rewritten; each supplement records its transitions
// separately, and the disposition guards read the base and every
// supplement folded together.
const routingMatrixSupplementGlob = "test-baseline-routing-matrix-supplement-*.csv"

// routingMatrixFinalViewGlob matches the append-only final-view files that
// resolve every remaining blocked row into an exclusion outcome. A final-view
// row differs from a supplement row in direction: it may never carry a landing
// path, and it must carry a non-empty note anchoring the resolution record.
const routingMatrixFinalViewGlob = "test-baseline-routing-matrix-final-*.csv"

// routingMatrixRegressionGlob matches the append-only regression-fulfillment
// files that resolve an excluded row back into a backed disposition once a
// later resolution implements the surface the exclusion recorded as
// unimplemented. This is the only sanctioned direction out of an exclusion:
// the fold runs after every final view, so it acts on rows that are excluded
// in the synthesized view, and it demands the full disposition proof (a
// disposed status, a real landing path, and a non-empty fulfillment anchor).
const routingMatrixRegressionGlob = "test-baseline-routing-matrix-regression-*.csv"

// exclusionFinalStatuses are the terminal outcomes a final-view row may assign
// to a still-blocked base row. They never admit a landing path and never
// exempt a file from the presence guard: an exclusion is a recorded decision
// not to implement a surface, not a licence to land its tests.
var exclusionFinalStatuses = map[string]struct{}{
	"excluded":             {},
	"erratum-reclassified": {},
}

// blockedFinalStatuses are the base-matrix outcomes a supplement row may
// transition away from. A supplement may only act on a row still awaiting a
// later change; it can never re-open a row that is already disposed, archived,
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
	// Note anchors an exclusion outcome to its resolution record. It is
	// populated only when a final-view file folds a row into an exclusion
	// status, so a row that reaches an exclusion status without going through
	// that fold carries no anchor and the closure guard can catch it.
	Note string
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
	for _, finalView := range routingMatrixFinalViewFiles(t, evidenceRoot) {
		applyRoutingMatrixExclusions(t, finalView, rows, byGois)
	}
	for _, regression := range routingMatrixRegressionFiles(t, evidenceRoot) {
		applyRoutingMatrixRegressionFulfillments(t, regression, rows, byGois)
	}
	return rows
}

// routingMatrixRegressionFiles returns the regression-fulfillment CSVs in
// deterministic order, mirroring the supplement and final-view folding.
func routingMatrixRegressionFiles(t *testing.T, evidenceRoot string) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(evidenceRoot, routingMatrixRegressionGlob))
	if err != nil {
		t.Fatalf("glob routing matrix regression fulfillments: %v", err)
	}
	sort.Strings(matches)
	return matches
}

// applyRoutingMatrixRegressionFulfillments folds one regression-fulfillment
// file into rows. The legality checks make this the exact dual of an
// exclusion, and strictly narrower: the target row must currently be
// "excluded" in the synthesized view — an erratum-reclassified row records a
// lineage correction that carries no fulfillment obligation, and a disposed,
// archived, or blocked row was never excluded to begin with, so every one of
// those fails closed. The outcome must be a disposed status backed by a real
// landing path, and the note must stay non-empty so the fulfillment remains
// anchored to its resolution record. A row folded here exits the exclusion
// presence guard and enters the landing-path consumption exactly as any other
// disposed row: no assertion is weakened, the row simply changes category
// with full proof attached.
func applyRoutingMatrixRegressionFulfillments(t *testing.T, path string, rows []routingMatrixRow, byGois map[string]int) {
	t.Helper()

	records := readCsvRecords(t, path)
	header := csvHeader(t, path, records)
	goisIndex := header("gois_path")
	statusIndex := header("final_status")
	landingIndex := header("wicket_landing_path")
	noteIndex := header("note")

	base := filepath.Base(path)
	for rowNo, record := range records[1:] {
		if len(record) <= goisIndex || len(record) <= statusIndex ||
			len(record) <= landingIndex || len(record) <= noteIndex {
			t.Fatalf("%s row %d has too few columns", base, rowNo+2)
		}
		gois := strings.TrimSpace(record[goisIndex])
		idx, ok := byGois[gois]
		if !ok {
			t.Fatalf("%s row %d fulfills unknown gois_path %q", base, rowNo+2, gois)
		}
		if _, exclusion := exclusionFinalStatuses[rows[idx].FinalStatus]; !exclusion {
			t.Fatalf("%s row %d fulfills gois_path %q whose current status %q is not an exclusion", base, rowNo+2, gois, rows[idx].FinalStatus)
		}
		if rows[idx].FinalStatus == "erratum-reclassified" {
			t.Fatalf("%s row %d fulfills gois_path %q whose erratum reclassification records no fulfillment obligation", base, rowNo+2, gois)
		}
		status := strings.TrimSpace(record[statusIndex])
		if _, disposed := disposedFinalStatuses[status]; !disposed {
			t.Fatalf("%s row %d moves gois_path %q to non-disposed status %q", base, rowNo+2, gois, status)
		}
		landing := strings.TrimSpace(record[landingIndex])
		if landing == "" || landing == "-" {
			t.Fatalf("%s row %d fulfills gois_path %q but names no landing path", base, rowNo+2, gois)
		}
		note := strings.TrimSpace(record[noteIndex])
		if note == "" {
			t.Fatalf("%s row %d fulfills gois_path %q without a fulfillment anchor", base, rowNo+2, gois)
		}
		rows[idx].FinalStatus = status
		rows[idx].LandingPath = landing
		rows[idx].Note = note
	}
}

// routingMatrixFinalViewFiles returns the final-view CSVs in deterministic
// order, mirroring the supplement folding.
func routingMatrixFinalViewFiles(t *testing.T, evidenceRoot string) []string {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(evidenceRoot, routingMatrixFinalViewGlob))
	if err != nil {
		t.Fatalf("glob routing matrix final views: %v", err)
	}
	sort.Strings(matches)
	return matches
}

// applyRoutingMatrixExclusions folds one final-view file into rows. The
// legality checks run in the opposite direction from a supplement: the target
// row must still be blocked, the outcome must be an exclusion status, the
// landing path must be EMPTY (an exclusion backed by a landing path is a
// contradiction), and the note must be non-empty so every exclusion stays
// anchored to its resolution record.
func applyRoutingMatrixExclusions(t *testing.T, path string, rows []routingMatrixRow, byGois map[string]int) {
	t.Helper()

	records := readCsvRecords(t, path)
	header := csvHeader(t, path, records)
	goisIndex := header("gois_path")
	statusIndex := header("final_status")
	landingIndex := header("wicket_landing_path")
	noteIndex := header("note")

	base := filepath.Base(path)
	for rowNo, record := range records[1:] {
		if len(record) <= goisIndex || len(record) <= statusIndex ||
			len(record) <= landingIndex || len(record) <= noteIndex {
			t.Fatalf("%s row %d has too few columns", base, rowNo+2)
		}
		gois := strings.TrimSpace(record[goisIndex])
		idx, ok := byGois[gois]
		if !ok {
			t.Fatalf("%s row %d excludes unknown gois_path %q", base, rowNo+2, gois)
		}
		if _, blocked := blockedFinalStatuses[rows[idx].FinalStatus]; !blocked {
			t.Fatalf("%s row %d excludes gois_path %q whose current status %q is not blocked", base, rowNo+2, gois, rows[idx].FinalStatus)
		}
		status := strings.TrimSpace(record[statusIndex])
		if _, exclusion := exclusionFinalStatuses[status]; !exclusion {
			t.Fatalf("%s row %d moves gois_path %q to non-exclusion status %q", base, rowNo+2, gois, status)
		}
		if landing := strings.TrimSpace(record[landingIndex]); landing != "" && landing != "-" {
			t.Fatalf("%s row %d excludes gois_path %q but carries landing path %q", base, rowNo+2, gois, landing)
		}
		note := strings.TrimSpace(record[noteIndex])
		if note == "" {
			t.Fatalf("%s row %d excludes gois_path %q without a resolution anchor", base, rowNo+2, gois)
		}
		rows[idx].FinalStatus = status
		rows[idx].LandingPath = ""
		rows[idx].Note = note
	}
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
