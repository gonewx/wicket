package e2e_test

import "testing"

// TestFinalStatusCategoryConsistencyE2E pins the set relationships between the
// final-status categories the disposition guards rely on. The guards fold
// supplements and final views by membership tests against these sets, so a
// status quietly added to two categories (or missing from the known set)
// would change folding legality without any CSV changing. Exclusion statuses
// must never overlap the disposed set (they would gain a landing-path
// exemption) nor the blocked sets (they would gain a skip-stub obligation or
// become re-openable by a later override).
func TestFinalStatusCategoryConsistencyE2E(t *testing.T) {
	t.Parallel()

	categories := map[string]map[string]struct{}{
		"exclusionFinalStatuses": exclusionFinalStatuses,
		"blockedFinalStatuses":   blockedFinalStatuses,
		"blockedStubStatuses":    blockedStubStatuses,
		"disposedFinalStatuses":  disposedFinalStatuses,
	}
	for name, set := range categories {
		for status := range set {
			if _, ok := knownFinalStatuses[status]; !ok {
				t.Fatalf("%s member %q missing from knownFinalStatuses", name, status)
			}
		}
	}

	disjointPairs := [][2]string{
		{"exclusionFinalStatuses", "disposedFinalStatuses"},
		{"exclusionFinalStatuses", "blockedFinalStatuses"},
		{"exclusionFinalStatuses", "blockedStubStatuses"},
		{"blockedFinalStatuses", "disposedFinalStatuses"},
	}
	for _, pair := range disjointPairs {
		for status := range categories[pair[0]] {
			if _, overlap := categories[pair[1]][status]; overlap {
				t.Fatalf("status %q belongs to both %s and %s", status, pair[0], pair[1])
			}
		}
	}

	for status := range blockedStubStatuses {
		if _, ok := blockedFinalStatuses[status]; !ok {
			t.Fatalf("stub status %q is not a blocked status", status)
		}
	}
}
