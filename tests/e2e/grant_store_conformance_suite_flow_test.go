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
// flow for the whole seven-port family against the in-repo stores, with the
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

	if storagetest.SuiteVersion != "1.0.0" {
		t.Fatalf("SuiteVersion = %q, want %q", storagetest.SuiteVersion, "1.0.0")
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
// contract point. The suite must fail that run and name the violated case. A
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
	"time"

	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// overwritingStore violates the insert-only contract for authorization codes:
// a second write under an existing handle silently replaces the stored record
// instead of failing with storage.ErrDuplicateHandle.
type overwritingStore struct {
	codes map[string]*models.AuthorizationCode
}

func (s *overwritingStore) StoreAuthorizationCode(_ context.Context, handle string, code *models.AuthorizationCode) error {
	if s.codes == nil {
		s.codes = make(map[string]*models.AuthorizationCode)
	}
	s.codes[handle] = code
	return nil
}

func (s *overwritingStore) GetAuthorizationCode(_ context.Context, handle string) (*models.AuthorizationCode, error) {
	code, ok := s.codes[handle]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return code, nil
}

func (s *overwritingStore) RemoveAuthorizationCode(_ context.Context, handle string) error {
	delete(s.codes, handle)
	return nil
}

func (s *overwritingStore) RemoveExpired(_ context.Context, cutoff time.Time) (int, error) {
	count := 0
	for handle, code := range s.codes {
		if code.CreationTime.Add(time.Duration(code.Lifetime) * time.Second).Before(cutoff) {
			delete(s.codes, handle)
			count++
		}
	}
	return count, nil
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
`)

	cmd := exec.Command("mise", "exec", "go@1.27rc1", "--", "go", "test", "./"+scratchConformanceDir+"/", "-count=1")
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
