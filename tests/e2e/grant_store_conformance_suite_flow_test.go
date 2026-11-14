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

	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	"github.com/gonewx/wicket/storage/memory"
	"github.com/gonewx/wicket/storage/storagetest"
)

// TestGrantStoreConformanceSuiteRunsExternalE2E runs every public suite entry
// from this consumer package, which shares no package with the stores or the
// suite. The suite is a published contract harness: an adapter author imports
// it, supplies a fresh store factory, and runs. This pins the import-and-run
// flow for the whole port family against the in-repo stores, with the
// enhanced MAY surface enabled.
func TestGrantStoreConformanceSuiteRunsExternalE2E(t *testing.T) {
	t.Parallel()

	suites := map[string]func(t *testing.T){
		"authorization codes": func(t *testing.T) {
			t.Parallel()
			storagetest.RunAuthorizationCodeStoreSuite(t, func() storage.AuthorizationCodeStore {
				return storage_impl.NewAuthorizationCodeStore()
			}, storagetest.WithMay(true))
		},
		"refresh tokens": func(t *testing.T) {
			t.Parallel()
			storagetest.RunRefreshTokenStoreSuite(t, func() storage.RefreshTokenStore {
				return storage_impl.NewRefreshTokenStore()
			}, storagetest.WithMay(true))
		},
		"reference tokens": func(t *testing.T) {
			t.Parallel()
			storagetest.RunReferenceTokenStoreSuite(t, func() storage.ReferenceTokenStore {
				return storage_impl.NewReferenceTokenStore()
			}, storagetest.WithMay(true))
		},
		"user consents": func(t *testing.T) {
			t.Parallel()
			storagetest.RunUserConsentStoreSuite(t, func() storage.UserConsentStore {
				return storage_impl.NewUserConsentStore()
			}, storagetest.WithMay(true))
		},
		"persisted grants": func(t *testing.T) {
			t.Parallel()
			storagetest.RunPersistedGrantStoreSuite(t, func() storage.PersistedGrantStore {
				return memory.NewMemoryPersistedGrantStore()
			}, storagetest.WithMay(true))
		},
		"device flows": func(t *testing.T) {
			t.Parallel()
			storagetest.RunDeviceFlowStoreSuite(t, func() storage.DeviceFlowStore {
				return memory.NewMemoryDeviceFlowStore()
			}, storagetest.WithMay(true))
		},
		"backchannel requests": func(t *testing.T) {
			t.Parallel()
			storagetest.RunBackchannelAuthenticationRequestStoreSuite(t, func() storage.BackchannelAuthenticationRequestStore {
				return memory.NewMemoryBackchannelAuthenticationRequestStore()
			}, storagetest.WithMay(true))
		},
		"client registrations": func(t *testing.T) {
			t.Parallel()
			storagetest.RunClientRegistrationStoreSuite(t, func() storage.ClientRegistrationStore {
				return memory.NewMemoryClientRegistrationStore()
			}, storagetest.WithMay(true))
		},
		"pushed authorization requests": func(t *testing.T) {
			t.Parallel()
			storagetest.RunPushedAuthorizationRequestStoreSuite(t, func() storage.PushedAuthorizationRequestStore {
				return memory.NewMemoryPushedAuthorizationRequestStore()
			}, storagetest.WithMay(true))
		},
	}

	for name, run := range suites {
		t.Run(name, run)
	}
}

// credentialCarrier wraps a store and exposes the compliance credential the
// suite package documents: ConformsTo returns the suite version the adapter
// was verified against.
type credentialCarrier struct {
	storage.AuthorizationCodeStore
	version string
}

func (c credentialCarrier) ConformsTo() string { return c.version }

// TestGrantStoreConformanceSuiteVersionAndCredentialE2E pins the compliance
// credential convention: SuiteVersion identifies the verified contract
// version, a credentialed adapter running the suite passes the credential
// check, and the host-side assembly rule accepts exactly a matching
// credential.
func TestGrantStoreConformanceSuiteVersionAndCredentialE2E(t *testing.T) {
	t.Parallel()

	if storagetest.SuiteVersion != "1.1.0" {
		t.Fatalf("SuiteVersion = %q, want %q", storagetest.SuiteVersion, "1.1.0")
	}

	// A credentialed adapter whose version matches runs the full suite,
	// including the enhanced credential case.
	storagetest.RunAuthorizationCodeStoreSuite(t, func() storage.AuthorizationCodeStore {
		return credentialCarrier{
			AuthorizationCodeStore: storage_impl.NewAuthorizationCodeStore(),
			version:                storagetest.SuiteVersion,
		}
	}, storagetest.WithMay(true))

	// Host-side assembly rule: a mismatched credential is refused, and a
	// store without the method carries no credential at all.
	mismatched := credentialCarrier{
		AuthorizationCodeStore: storage_impl.NewAuthorizationCodeStore(),
		version:                "0.0.1",
	}
	if mismatched.ConformsTo() == storagetest.SuiteVersion {
		t.Fatal("mismatched credential equals SuiteVersion")
	}
	if _, carriesCredential := any(storage_impl.NewAuthorizationCodeStore()).(interface{ ConformsTo() string }); carriesCredential {
		t.Fatal("plain store unexpectedly carries a compliance credential")
	}
}

const scratchConformanceDir = "tests/e2e/scratch-conformance"

// TestGrantStoreConformanceSuiteRejectsViolationsE2E runs the suite the way a
// host vets an unknown adapter: against a store that violates one insert-only
// contract point, and against a store whose take looks the code up and
// deletes it in two separate steps. The suite must fail each run and name the
// violated case. A
// suite that passes a violating adapter could not serve as a compliance gate,
// so the run happens in a scratch package and its failure is the assertion.
func TestGrantStoreConformanceSuiteRejectsViolationsE2E(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("mise"); err != nil {
		t.Fatalf("locate mise toolchain: %v", err)
	}

	root := projectRoot(t)
	scratch := filepath.Join(root, scratchConformanceDir)
	if err := os.RemoveAll(scratch); err != nil {
		t.Fatalf("clear scratch suite package: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(scratch); err != nil {
			t.Logf("remove scratch suite package: %v", err)
		}
	})

	writeScratchFile(t, filepath.Join(scratch, "adapter.go"), `// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package scratchconformance

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// overwritingStore violates the insert-only contract for authorization codes:
// a second write under an existing handle silently replaces the stored record
// instead of failing with storage.ErrDuplicateHandle. Every other method
// honors the contract, so the insert-only case is the only one that fails.
type overwritingStore struct {
	mu    sync.Mutex
	codes map[string]*models.AuthorizationCode
}

func (s *overwritingStore) StoreAuthorizationCode(_ context.Context, handle string, code *models.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.codes == nil {
		s.codes = make(map[string]*models.AuthorizationCode)
	}
	s.codes[handle] = code
	return nil
}

func (s *overwritingStore) GetAuthorizationCode(_ context.Context, handle string) (*models.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.codes[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return code, nil
}

func (s *overwritingStore) TakeAuthorizationCode(_ context.Context, handle string) (*models.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.codes[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	delete(s.codes, handle)
	return code, nil
}

func (s *overwritingStore) RemoveAuthorizationCode(_ context.Context, handle string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, handle)
	return nil
}

func (s *overwritingStore) RemoveAuthorizationCodesByClient(_ context.Context, clientId string) (int, error) {
	return s.removeWhere(clientId, func(code *models.AuthorizationCode) string { return code.ClientId })
}

func (s *overwritingStore) RemoveAuthorizationCodesBySession(_ context.Context, sessionId string) (int, error) {
	return s.removeWhere(sessionId, func(code *models.AuthorizationCode) string { return code.SessionId })
}

func (s *overwritingStore) removeWhere(value string, field func(*models.AuthorizationCode) string) (int, error) {
	if value == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for handle, code := range s.codes {
		if field(code) == value {
			delete(s.codes, handle)
			count++
		}
	}
	return count, nil
}

func (s *overwritingStore) RemoveExpired(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for handle, code := range s.codes {
		if code.CreationTime.Add(time.Duration(code.Lifetime) * time.Second).Before(cutoff) {
			delete(s.codes, handle)
			count++
		}
	}
	return count, nil
}

// nonAtomicTakeStore honors the insert-only contract but takes a code in two
// locked steps, a lookup and then a delete, yielding in between: concurrent
// takers can all see the code before any of them deletes it.
type nonAtomicTakeStore struct {
	overwritingStore
}

func (s *nonAtomicTakeStore) StoreAuthorizationCode(_ context.Context, handle string, code *models.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.codes == nil {
		s.codes = make(map[string]*models.AuthorizationCode)
	}
	if _, exists := s.codes[handle]; exists {
		return storage.ErrDuplicateHandle
	}
	s.codes[handle] = code
	return nil
}

func (s *nonAtomicTakeStore) TakeAuthorizationCode(ctx context.Context, handle string) (*models.AuthorizationCode, error) {
	code, err := s.GetAuthorizationCode(ctx, handle)
	if err != nil {
		return nil, err
	}
	runtime.Gosched()
	if err := s.RemoveAuthorizationCode(ctx, handle); err != nil {
		return nil, err
	}
	return code, nil
}
`)

	writeScratchFile(t, filepath.Join(scratch, "adapter_test.go"), `// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package scratchconformance

import (
	"testing"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/storagetest"
)

func TestAdapterRunsSuite(t *testing.T) {
	storagetest.RunAuthorizationCodeStoreSuite(t, func() storage.AuthorizationCodeStore {
		return &overwritingStore{}
	}, storagetest.WithMay(true))
}

func TestNonAtomicTakeRunsSuite(t *testing.T) {
	storagetest.RunAuthorizationCodeStoreSuite(t, func() storage.AuthorizationCodeStore {
		return &nonAtomicTakeStore{}
	}, storagetest.WithMay(true))
}
`)

	cmd := exec.Command("mise", "exec", "go@"+readGoToolchainPin(t), "--", "go", "test", "./"+scratchConformanceDir+"/", "-count=1")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	combined := string(output) + stderr.String()
	if err == nil {
		t.Fatal("suite accepted a store that silently overwrites an existing handle")
	}
	if !strings.Contains(combined, "MUST/DuplicateHandleRejected") {
		t.Fatalf("suite failure output does not name the violated case:\n%s", combined)
	}
	if !strings.Contains(combined, "--- FAIL: TestNonAtomicTakeRunsSuite/MUST/TakeExactlyOnceUnderConcurrency") {
		t.Fatalf("suite accepted a non-atomic take or did not name the violated case:\n%s", combined)
	}
}

const scratchClientRegistrationDir = "tests/e2e/scratch-client-registration"

// TestGrantStoreConformanceSuiteRejectsTombstoneViolationE2E vets a client
// registration adapter that forgets removed client ids: after a removal it
// accepts a new registration under the same id. The suite must fail that run
// and name the tombstone case, from a scratch package of its own.
func TestGrantStoreConformanceSuiteRejectsTombstoneViolationE2E(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("mise"); err != nil {
		t.Fatalf("locate mise toolchain: %v", err)
	}

	root := projectRoot(t)
	scratch := filepath.Join(root, scratchClientRegistrationDir)
	if err := os.RemoveAll(scratch); err != nil {
		t.Fatalf("clear scratch suite package: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(scratch); err != nil {
			t.Logf("remove scratch suite package: %v", err)
		}
	})

	writeScratchFile(t, filepath.Join(scratch, "adapter.go"), `// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package scratchclientregistration

import (
	"context"
	"sync"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

type row struct {
	data     []byte
	revision int
	digest   string
	at       time.Time
}

// forgetfulStore violates the tombstone contract: removing a registration
// deletes it without a trace, so the client id can be registered again.
type forgetfulStore struct {
	mu   sync.Mutex
	rows map[string]row
}

func newForgetfulStore() *forgetfulStore { return &forgetfulStore{rows: map[string]row{}} }

func (s *forgetfulStore) encode(r *models.ClientRegistration, revision int) (row, error) {
	data, err := storage.EncodeClient(r.Client)
	return row{data: data, revision: revision, digest: r.RegistrationAccessTokenDigest, at: r.RegistrationTime}, err
}

func (s *forgetfulStore) RegisterClient(_ context.Context, r *models.ClientRegistration) (int, error) {
	encoded, err := s.encode(r, 1)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rows[r.Client.ClientId]; ok {
		return 0, storage.ErrDuplicateHandle
	}
	s.rows[r.Client.ClientId] = encoded
	return 1, nil
}

func (s *forgetfulStore) FindClientRegistration(_ context.Context, id string) (*models.ClientRegistration, error) {
	s.mu.Lock()
	stored, ok := s.rows[id]
	s.mu.Unlock()
	if !ok {
		return nil, storage.ErrNotFound
	}
	client, err := storage.DecodeClient(stored.data)
	if err != nil {
		return nil, err
	}
	return &models.ClientRegistration{Client: client, Revision: stored.revision, RegistrationAccessTokenDigest: stored.digest, RegistrationTime: stored.at}, nil
}

func (s *forgetfulStore) FindClientById(ctx context.Context, id string) (*models.Client, error) {
	r, err := s.FindClientRegistration(ctx, id)
	if err != nil {
		return nil, err
	}
	return r.Client, nil
}

func (s *forgetfulStore) UpdateClientRegistration(_ context.Context, r *models.ClientRegistration, expected int) (int, error) {
	encoded, err := s.encode(r, expected+1)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.rows[r.Client.ClientId]
	if !ok {
		return 0, storage.ErrNotFound
	}
	if current.revision != expected {
		return 0, storage.ErrVersionConflict
	}
	s.rows[r.Client.ClientId] = encoded
	return encoded.revision, nil
}

func (s *forgetfulStore) RemoveClientRegistration(_ context.Context, id string, expected int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.rows[id]
	if !ok {
		return storage.ErrNotFound
	}
	if current.revision != expected {
		return storage.ErrVersionConflict
	}
	delete(s.rows, id)
	return nil
}

func (s *forgetfulStore) FindClientsByAllowedOrigin(_ context.Context, origin string) ([]*models.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	matches := []*models.Client{}
	for _, stored := range s.rows {
		client, err := storage.DecodeClient(stored.data)
		if err != nil {
			return nil, err
		}
		for _, allowed := range client.AllowedCorsOrigins {
			if allowed == origin {
				matches = append(matches, client)
				break
			}
		}
	}
	return matches, nil
}
`)

	writeScratchFile(t, filepath.Join(scratch, "adapter_test.go"), `// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package scratchclientregistration

import (
	"testing"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/storagetest"
)

func TestAdapterRunsSuite(t *testing.T) {
	storagetest.RunClientRegistrationStoreSuite(t, func() storage.ClientRegistrationStore {
		return newForgetfulStore()
	}, storagetest.WithMay(true))
}
`)

	cmd := exec.Command("mise", "exec", "go@"+readGoToolchainPin(t), "--", "go", "test", "./"+scratchClientRegistrationDir+"/", "-count=1")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	combined := string(output) + stderr.String()
	if err == nil {
		t.Fatal("suite accepted a client registration store that leaves no tombstone")
	}
	if !strings.Contains(combined, "--- FAIL: TestAdapterRunsSuite/MUST/TombstoneBlocksReRegistration") {
		t.Fatalf("suite failure output does not name the violated case:\n%s", combined)
	}
	// The violation is the only one: every other case of the run passes.
	if strings.Count(combined, "--- FAIL: TestAdapterRunsSuite/") != 1 {
		t.Fatalf("suite failed more cases than the tombstone one:\n%s", combined)
	}
}

const scratchPushedAuthorizationDir = "tests/e2e/scratch-pushed-authorization"

// TestGrantStoreConformanceSuiteRejectsEntryExpirationReclamationE2E vets a
// pushed authorization request adapter that reclaims on EntryExpiration
// instead of RetentionExpiration: it drops requests still inside their
// interaction round trip. The suite must fail that run and name the
// round-trip retention case, from a scratch package of its own.
func TestGrantStoreConformanceSuiteRejectsEntryExpirationReclamationE2E(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("mise"); err != nil {
		t.Fatalf("locate mise toolchain: %v", err)
	}

	root := projectRoot(t)
	scratch := filepath.Join(root, scratchPushedAuthorizationDir)
	if err := os.RemoveAll(scratch); err != nil {
		t.Fatalf("clear scratch suite package: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(scratch); err != nil {
			t.Logf("remove scratch suite package: %v", err)
		}
	})

	writeScratchFile(t, filepath.Join(scratch, "adapter.go"), `// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package scratchpushedauthorization

import (
	"context"
	"sync"
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// eagerStore violates the reclamation contract: RemoveExpired looks at
// EntryExpiration, so a request still inside its round trip is dropped.
type eagerStore struct {
	mu   sync.Mutex
	rows map[string]models.PushedAuthorizationRequest
}

func newEagerStore() *eagerStore {
	return &eagerStore{rows: map[string]models.PushedAuthorizationRequest{}}
}

func copyRequest(r models.PushedAuthorizationRequest) *models.PushedAuthorizationRequest {
	r.Payload = append([]byte(nil), r.Payload...)
	return &r
}

func (s *eagerStore) StorePushedAuthorizationRequest(_ context.Context, key string, r *models.PushedAuthorizationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rows[key]; ok {
		return storage.ErrDuplicateHandle
	}
	s.rows[key] = *copyRequest(*r)
	return nil
}

func (s *eagerStore) GetPushedAuthorizationRequest(_ context.Context, key string) (*models.PushedAuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return copyRequest(r), nil
}

func (s *eagerStore) TakePushedAuthorizationRequest(_ context.Context, key string) (*models.PushedAuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	delete(s.rows, key)
	return copyRequest(r), nil
}

func (s *eagerStore) RemoveExpired(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, r := range s.rows {
		if r.EntryExpiration.Before(cutoff) {
			delete(s.rows, key)
			removed++
		}
	}
	return removed, nil
}
`)

	writeScratchFile(t, filepath.Join(scratch, "adapter_test.go"), `// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package scratchpushedauthorization

import (
	"testing"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/storagetest"
)

func TestAdapterRunsSuite(t *testing.T) {
	storagetest.RunPushedAuthorizationRequestStoreSuite(t, func() storage.PushedAuthorizationRequestStore {
		return newEagerStore()
	}, storagetest.WithMay(true))
}
`)

	cmd := exec.Command("mise", "exec", "go@"+readGoToolchainPin(t), "--", "go", "test", "./"+scratchPushedAuthorizationDir+"/", "-count=1")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	combined := string(output) + stderr.String()
	if err == nil {
		t.Fatal("suite accepted a pushed authorization request store that reclaims on EntryExpiration")
	}
	if !strings.Contains(combined, "--- FAIL: TestAdapterRunsSuite/MUST/RemoveExpiredKeepsRecordsInRoundTrip") {
		t.Fatalf("suite failure output does not name the violated case:\n%s", combined)
	}
}

func writeScratchFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create scratch directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write scratch file: %v", err)
	}
}
