// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replaytest

import (
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/gonewx/wicket/replay"
)

// A suite that fails marks the test it runs in as failed, so the checks that
// the suite rejects bad doubles cannot run it in this process. They run this
// test binary again instead, selecting TestDoubleRunsSuite and naming the
// double through doubleEnv, and read the child's exit status and output.

const (
	doubleEnv        = "WICKET_REPLAYTEST_DOUBLE"
	childEntry       = "TestDoubleRunsSuite"
	referenceDouble  = "reference"
	referenceWithMay = "reference-with-may"
	failedMustPrefix = "--- FAIL: " + childEntry + "/MUST/"
	passedMustPrefix = "--- PASS: " + childEntry + "/MUST/"
)

// badDoubles lists every bad double with the MUST case that has to reject it.
// only marks the doubles for which that case has to be the sole failing MUST
// case: the two that read a clock behave correctly for every instant the
// suite uses except the one in the real past.
var badDoubles = []struct {
	name     string
	flaw     flaw
	mustFail string
	only     bool
}{
	{"B1-check-then-write", flawCheckThenWrite, "ConcurrentRegisterSingleWinner", false},
	{"B2-forgets-expired-by-own-clock", flawForgetsExpiredByOwnClock, "ExpiredButUnreclaimedIsStillDuplicate", true},
	{"B3-upsert", flawUpsert, "RegisterDuplicateReturnsSentinel", false},
	{"B4-foreign-duplicate-error", flawForeignDuplicateError, "RegisterDuplicateReturnsSentinel", false},
	{"B5-duplicate-overwrites-expiry", flawDuplicateOverwritesExpiry, "DuplicateLeavesExpiryUnchanged", false},
	{"B6-removes-everything", flawRemovesEverything, "RemoveExpiredStrictlyBeforeCutoff", false},
	{"B7-inclusive-cutoff", flawInclusiveCutoff, "RemoveExpiredStrictlyBeforeCutoff", false},
	{"B8-refuses-past-expiry", flawRefusesPastExpiry, "ExpiredButUnreclaimedIsStillDuplicate", true},
	{"B9-accepts-zero-expiry", flawAcceptsZeroExpiry, "RejectsEmptyKeyAndZeroExpiry", false},
	{"stale-credential", flawStaleCredential, "CredentialMatchesWhenExposed", true},
}

// TestDoubleRunsSuite is the child entry. Run normally it does nothing; with
// doubleEnv set it runs the MUST cases against the named double.
func TestDoubleRunsSuite(t *testing.T) {
	name := os.Getenv(doubleEnv)
	if name == "" {
		return
	}
	if name == referenceDouble {
		RunRegistrySuite(t, func() replay.Registry { return newFakeRegistry(flawNone) })
		return
	}
	if name == referenceWithMay {
		RunRegistrySuite(t, func() replay.Registry { return newFakeRegistry(flawNone) }, WithMay(true))
		return
	}
	for _, double := range badDoubles {
		if double.name == name {
			RunRegistrySuite(t, func() replay.Registry { return newFakeRegistry(double.flaw) })
			return
		}
	}
	t.Fatalf("%s names an unknown double %q", doubleEnv, name)
}

// runChildSuite runs the suite against the named double in a child process
// and returns its combined output and whether it exited with a failure.
func runChildSuite(t *testing.T, double string) (output string, failed bool) {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=^"+childEntry+"$", "-test.v", "-test.count=1", "-test.timeout=2m")
	cmd.Env = append(os.Environ(), doubleEnv+"="+double)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), false
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("running the suite against %s in a child process: %v", double, err)
	}
	return string(out), true
}

// mustCasesReported returns the names of the MUST cases the child's verbose
// output reports with the given result prefix.
func mustCasesReported(output, prefix string) []string {
	var names []string
	for _, line := range strings.Split(output, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), prefix)
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(rest, " ")
		names = append(names, name)
	}
	return names
}

func TestSuiteRejectsBadDoubles(t *testing.T) {
	for _, double := range badDoubles {
		t.Run(double.name, func(t *testing.T) {
			output, failed := runChildSuite(t, double.name)
			if !failed {
				t.Fatalf("the suite accepted %s; child output:\n%s", double.name, output)
			}
			rejectedBy := mustCasesReported(output, failedMustPrefix)
			if !slices.Contains(rejectedBy, double.mustFail) {
				t.Fatalf("MUST/%s did not reject %s; failing MUST cases: %v; child output:\n%s", double.mustFail, double.name, rejectedBy, output)
			}
			if double.only && len(rejectedBy) != 1 {
				t.Fatalf("%s must be rejected by MUST/%s alone; failing MUST cases: %v", double.name, double.mustFail, rejectedBy)
			}
		})
	}
}

// Without WithMay the suite registers the MUST cases and nothing else: no MAY
// subtest exists, and none is reported as skipped.
func TestSuiteRegistersOnlyMustCasesByDefault(t *testing.T) {
	output, failed := runChildSuite(t, referenceDouble)
	if failed {
		t.Fatalf("the suite rejected the reference double; child output:\n%s", output)
	}

	want := []string{
		"RegisterFirstSucceeds",
		"RegisterDuplicateReturnsSentinel",
		"DuplicateLeavesExpiryUnchanged",
		"ExpiredButUnreclaimedIsStillDuplicate",
		"RemoveExpiredStrictlyBeforeCutoff",
		"RemoveExpiredEmptyAndRepeat",
		"ReRegisterAfterReclaim",
		"DistinctKeysIndependent",
		"ConcurrentRegisterSingleWinner",
		"ConcurrentDistinctKeysAllSucceed",
		"RejectsEmptyKeyAndZeroExpiry",
		"CancelledContext",
		"ExpiryComparedAsInstant",
		"CredentialMatchesWhenExposed",
	}
	if got := mustCasesReported(output, passedMustPrefix); !slices.Equal(got, want) {
		t.Fatalf("passing MUST cases = %v, want %v", got, want)
	}
	for _, unwanted := range []string{childEntry + "/MAY/", "--- SKIP"} {
		if strings.Contains(output, unwanted) {
			t.Fatalf("child output contains %q although MAY cases were not enabled:\n%s", unwanted, output)
		}
	}
}

// With WithMay the three MAY cases are registered under their fixed names and
// actually run: a child process running the suite with WithMay(true) reports
// each of them as passed.
func TestSuiteRegistersMayCasesWhenEnabled(t *testing.T) {
	var names []string
	for _, c := range mayCases {
		names = append(names, c.name)
	}
	want := []string{"HighContentionSingleWinner", "NoBackgroundGoroutines", "SubSecondExpiryNotRoundedDown"}
	if !slices.Equal(names, want) {
		t.Fatalf("MAY cases = %v, want %v", names, want)
	}

	output, failed := runChildSuite(t, referenceWithMay)
	if failed {
		t.Fatalf("the suite with MAY cases rejected the reference double; child output:\n%s", output)
	}
	if got := mustCasesReported(output, "--- PASS: "+childEntry+"/MAY/"); !slices.Equal(got, want) {
		t.Fatalf("passing MAY cases = %v, want %v; child output:\n%s", got, want, output)
	}
}
