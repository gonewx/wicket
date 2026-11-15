// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/keymgmt/keymgmttest"
	"github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/session/sessiontest"
)

// TestSessionAndKeymgmtConformanceSuiteRunsExternalE2E runs every public
// suite entry from this consumer package, which shares no package with the
// stores or the suites. A suite is a published contract harness: an adapter
// author imports it, supplies a fresh store factory, and runs. This pins the
// import-and-run flow for both subsystem ports against the in-repo memory
// stores, with the enhanced MAY surface enabled.
func TestSessionAndKeymgmtConformanceSuiteRunsExternalE2E(t *testing.T) {
	t.Parallel()

	clock := wiringClockAt{at: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)}
	sessiontest.RunSessionStoreSuite(t, func() session.Store {
		return session.NewMemoryStore(clock)
	}, sessiontest.WithMay(true))

	keymgmttest.RunRecordStoreSuite(t, func() keymgmt.RecordStore {
		return keymgmt.NewMemoryRecordStore()
	}, keymgmttest.WithMay(true))
}

type wiringClockAt struct {
	at time.Time
}

func (c wiringClockAt) Now() time.Time { return c.at }

// sessionCredentialCarrier wraps a session store and exposes the compliance
// credential the suite package documents.
type sessionCredentialCarrier struct {
	session.Store
	version string
}

func (c sessionCredentialCarrier) ConformsTo() string { return c.version }

// keymgmtCredentialCarrier wraps a key record store and exposes the
// compliance credential the suite package documents.
type keymgmtCredentialCarrier struct {
	keymgmt.RecordStore
	version string
}

func (c keymgmtCredentialCarrier) ConformsTo() string { return c.version }

// TestSessionAndKeymgmtConformanceSuiteVersionAndCredentialE2E pins the
// compliance credential convention for both suites: SuiteVersion identifies
// the verified contract version, a credentialed adapter running the suite
// passes the credential check, and the host-side assembly rule accepts
// exactly a matching credential.
func TestSessionAndKeymgmtConformanceSuiteVersionAndCredentialE2E(t *testing.T) {
	t.Parallel()

	if sessiontest.SuiteVersion != "2.0.0" {
		t.Fatalf("sessiontest.SuiteVersion = %q, want %q", sessiontest.SuiteVersion, "2.0.0")
	}
	if keymgmttest.SuiteVersion != "2.0.0" {
		t.Fatalf("keymgmttest.SuiteVersion = %q, want %q", keymgmttest.SuiteVersion, "2.0.0")
	}
	if sessiontest.SuiteVersion != keymgmttest.SuiteVersion {
		t.Fatalf("suite versions diverge: sessiontest %q vs keymgmttest %q", sessiontest.SuiteVersion, keymgmttest.SuiteVersion)
	}

	clock := wiringClockAt{at: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)}

	// A credentialed adapter whose version matches runs the full suite,
	// including the enhanced credential case.
	sessiontest.RunSessionStoreSuite(t, func() session.Store {
		return sessionCredentialCarrier{Store: session.NewMemoryStore(clock), version: sessiontest.SuiteVersion}
	}, sessiontest.WithMay(true))
	keymgmttest.RunRecordStoreSuite(t, func() keymgmt.RecordStore {
		return keymgmtCredentialCarrier{RecordStore: keymgmt.NewMemoryRecordStore(), version: keymgmttest.SuiteVersion}
	}, keymgmttest.WithMay(true))

	// Host-side assembly rule: a mismatched credential is refused, and a
	// store without the method carries no credential at all.
	if got := (sessionCredentialCarrier{version: "0.0.1"}).ConformsTo(); got == sessiontest.SuiteVersion {
		t.Fatal("mismatched session credential equals SuiteVersion")
	}
	if got := (keymgmtCredentialCarrier{version: "0.0.1"}).ConformsTo(); got == keymgmttest.SuiteVersion {
		t.Fatal("mismatched keymgmt credential equals SuiteVersion")
	}
	if _, carries := any(session.NewMemoryStore(clock)).(interface{ ConformsTo() string }); carries {
		t.Fatal("plain session store unexpectedly carries a compliance credential")
	}
	if _, carries := any(keymgmt.NewMemoryRecordStore()).(interface{ ConformsTo() string }); carries {
		t.Fatal("plain keymgmt store unexpectedly carries a compliance credential")
	}
}

const scratchSessionKeymgmtDir = "tests/e2e/scratch-session-keymgmt"

// TestSessionAndKeymgmtConformanceSuiteRejectsViolationsE2E runs the suites
// the way a host vets an unknown adapter: against stores that each violate
// one contract point. The suites must fail those runs and name the violated
// cases. Suites that passed violating adapters could not serve as compliance
// gates, so the runs happen in a scratch package and their failure is the
// assertion.
func TestSessionAndKeymgmtConformanceSuiteRejectsViolationsE2E(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("mise"); err != nil {
		t.Fatalf("locate mise toolchain: %v", err)
	}

	root := projectRoot(t)
	scratch := filepath.Join(root, scratchSessionKeymgmtDir)
	if err := os.RemoveAll(scratch); err != nil {
		t.Fatalf("clear scratch suite package: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(scratch); err != nil {
			t.Logf("remove scratch suite package: %v", err)
		}
	})

	writeScratchFile(t, filepath.Join(scratch, "adapters.go"), `// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package scratchsessionkeymgmt

import (
	"context"
	"time"

	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/session"
)

// ghostReadStore violates the session read-miss contract: a lookup that
// misses returns a nil record with a nil error instead of the sentinel.
type ghostReadStore struct {
	sessions map[string]*session.Record
}

func (s *ghostReadStore) GetSession(_ context.Context, sessionID string) (*session.Record, error) {
	rec, ok := s.sessions[sessionID]
	if !ok {
		return nil, nil
	}
	return rec, nil
}

func (s *ghostReadStore) CreateSession(_ context.Context, rec *session.Record) error {
	if s.sessions == nil {
		s.sessions = make(map[string]*session.Record)
	}
	s.sessions[rec.SessionID] = rec
	return nil
}

func (s *ghostReadStore) UpdateSession(_ context.Context, rec *session.Record) error {
	if s.sessions == nil {
		s.sessions = make(map[string]*session.Record)
	}
	s.sessions[rec.SessionID] = rec
	return nil
}

func (s *ghostReadStore) DeleteSession(_ context.Context, sessionID string) error {
	delete(s.sessions, sessionID)
	return nil
}

func (s *ghostReadStore) GetSessionsBySubjectID(_ context.Context, _ string) ([]*session.Record, error) {
	return nil, nil
}

func (s *ghostReadStore) DeleteSessionsBySubjectID(_ context.Context, _ string) (int, error) {
	return 0, nil
}

func (s *ghostReadStore) AddClientID(_ context.Context, _, _ string) error {
	return nil
}

func (s *ghostReadStore) DeleteExpired(_ context.Context, _ time.Time) (int, error) {
	return 0, nil
}

// overwritingRecordStore violates the key record insert-only contract: a
// second create under an existing handle silently replaces the stored record
// instead of failing with keymgmt.ErrDuplicateKey.
type overwritingRecordStore struct {
	records map[string]*keymgmt.Record
}

func (s *overwritingRecordStore) List(_ context.Context) ([]*keymgmt.Record, error) {
	out := make([]*keymgmt.Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	return out, nil
}

func (s *overwritingRecordStore) Get(_ context.Context, handle string) (*keymgmt.Record, error) {
	r, ok := s.records[handle]
	if !ok {
		return nil, keymgmt.ErrRecordNotFound
	}
	return r, nil
}

func (s *overwritingRecordStore) Create(_ context.Context, record *keymgmt.Record) error {
	if s.records == nil {
		s.records = make(map[string]*keymgmt.Record)
	}
	s.records[record.Handle] = record
	return nil
}

func (s *overwritingRecordStore) Update(_ context.Context, record *keymgmt.Record, _ uint64) error {
	if s.records == nil {
		s.records = make(map[string]*keymgmt.Record)
	}
	s.records[record.Handle] = record
	return nil
}

func (s *overwritingRecordStore) Delete(_ context.Context, handle string) error {
	delete(s.records, handle)
	return nil
}
`)

	writeScratchFile(t, filepath.Join(scratch, "adapters_test.go"), `// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package scratchsessionkeymgmt

import (
	"testing"

	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/keymgmt/keymgmttest"
	"github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/session/sessiontest"
)

func TestGhostReadStoreRunsSessionSuite(t *testing.T) {
	sessiontest.RunSessionStoreSuite(t, func() session.Store {
		return &ghostReadStore{}
	})
}

func TestOverwritingRecordStoreRunsKeymgmtSuite(t *testing.T) {
	keymgmttest.RunRecordStoreSuite(t, func() keymgmt.RecordStore {
		return &overwritingRecordStore{}
	})
}
`)

	cmd := exec.Command("mise", "exec", "go@"+readGoToolchainPin(t), "--", "go", "test", "./"+scratchSessionKeymgmtDir+"/", "-count=1")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	combined := string(output) + stderr.String()
	if err == nil {
		t.Fatal("suites accepted stores that violate their contracts")
	}
	if !strings.Contains(combined, "MUST/MissingReadReturnsSentinel") {
		t.Fatalf("session suite failure output does not name the violated case:\n%s", combined)
	}
	if !strings.Contains(combined, "MUST/DuplicateHandleRejected") {
		t.Fatalf("keymgmt suite failure output does not name the violated case:\n%s", combined)
	}
}
