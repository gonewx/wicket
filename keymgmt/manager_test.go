// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket/dp"
)

// fakeClock is an injectable, advanceable time source so lifecycle decisions are
// deterministic without reading the wall clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// reversibleProvider is a reversible protector that tags protected bytes so a
// test can prove protection is actually applied.
type reversibleProvider struct{}

func (reversibleProvider) Create(string) dp.DataProtector { return reversibleProtector{} }

type reversibleProtector struct{}

func (reversibleProtector) Protect(data []byte) []byte {
	return append([]byte("protected:"), data...)
}

func (reversibleProtector) Unprotect(data []byte) ([]byte, error) {
	if len(data) < len("protected:") {
		return nil, ErrConfiguration
	}
	return data[len("protected:"):], nil
}

func enabledConfig() Config {
	return Config{
		Enabled:            true,
		AutoCreate:         true,
		RotationInterval:   time.Hour,
		ActivationLeadTime: 10 * time.Minute,
		RetentionDuration:  20 * time.Minute,
		AllowedAlgorithms:  []string{AlgES256},
		DefaultAlgorithm:   AlgES256,
		CacheTTL:           time.Minute,
		ClockSkew:          time.Minute,
	}
}

func newTestManager(t *testing.T, cfg Config, store RecordStore, clock Clock) *Manager {
	t.Helper()
	if store == nil {
		store = NewMemoryRecordStore()
	}
	return NewManager(cfg, store, reversibleProvider{}, clock, rand.Reader, nil)
}

func countPhase(t *testing.T, store RecordStore, phase Phase) int {
	t.Helper()
	records, err := store.List()
	if err != nil {
		t.Fatalf("list records: %v", err)
	}
	n := 0
	for _, r := range records {
		if r.Phase == phase {
			n++
		}
	}
	return n
}

func TestManagerBootstrapProducesActiveSigningKey(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	m := newTestManager(t, enabledConfig(), store, clock)

	candidates, err := m.SigningCandidates()
	if err != nil {
		t.Fatalf("signing candidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("signing candidate count = %d, want 1", len(candidates))
	}
	if candidates[0].Credential.Algorithm != AlgES256 {
		t.Fatalf("algorithm = %q, want %q", candidates[0].Credential.Algorithm, AlgES256)
	}
	if candidates[0].Credential.Kid == "" {
		t.Fatal("signing credential missing kid")
	}
	if _, ok := candidates[0].Credential.Key.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("signing key type = %T, want *ecdsa.PrivateKey", candidates[0].Credential.Key)
	}
	if got := countPhase(t, store, PhaseActive); got != 1 {
		t.Fatalf("active key count = %d, want 1", got)
	}
}

func TestManagerValidationKeysExposeOnlyPublicMaterial(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	m := newTestManager(t, enabledConfig(), nil, clock)

	// Trigger bootstrap.
	signing, err := m.SigningCandidates()
	if err != nil {
		t.Fatalf("signing candidates: %v", err)
	}
	keys, err := m.ValidationKeys()
	if err != nil {
		t.Fatalf("validation keys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("validation key count = %d, want 1", len(keys))
	}
	if keys[0].KeyId != signing[0].Credential.Kid {
		t.Fatalf("validation kid %q != signing kid %q", keys[0].KeyId, signing[0].Credential.Kid)
	}
	if _, ok := keys[0].Key.(*ecdsa.PublicKey); !ok {
		t.Fatalf("validation key type = %T, want *ecdsa.PublicKey (public material only)", keys[0].Key)
	}
	if _, ok := keys[0].Key.(*ecdsa.PrivateKey); ok {
		t.Fatal("validation key leaked a private key")
	}
}

func TestManagerLifecycleTransitions(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	cfg := enabledConfig()
	m := newTestManager(t, cfg, store, clock)

	// Bootstrap the first active key.
	if _, err := m.SigningCandidates(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if got := countPhase(t, store, PhaseActive); got != 1 {
		t.Fatalf("after bootstrap active = %d, want 1", got)
	}

	// Advance to the rotation warm-up point; a candidate must be created.
	clock.advance(cfg.RotationInterval - cfg.ActivationLeadTime + time.Second)
	m.invalidateCache()
	if _, err := m.SigningCandidates(); err != nil {
		t.Fatalf("rotation warm-up: %v", err)
	}
	if got := countPhase(t, store, PhaseCandidate); got != 1 {
		t.Fatalf("candidate count = %d, want 1", got)
	}

	// Advance past the original key's expiry: the candidate activates and the old
	// active moves to retained.
	clock.advance(cfg.ActivationLeadTime + time.Second)
	m.invalidateCache()
	if _, err := m.SigningCandidates(); err != nil {
		t.Fatalf("activation: %v", err)
	}
	if got := countPhase(t, store, PhaseActive); got != 1 {
		t.Fatalf("post-rotation active = %d, want 1", got)
	}
	if got := countPhase(t, store, PhaseRetained); got != 1 {
		t.Fatalf("post-rotation retained = %d, want 1", got)
	}

	// Advance past retention: the retained key retires and drops out of JWKS
	// while the current active key keeps signing.
	clock.advance(cfg.RetentionDuration + cfg.ClockSkew + time.Second)
	m.invalidateCache()
	keys, err := m.ValidationKeys()
	if err != nil {
		t.Fatalf("post-retention validation: %v", err)
	}
	if got := countPhase(t, store, PhaseRetired); got != 1 {
		t.Fatalf("retired count = %d, want 1", got)
	}
	if got := countPhase(t, store, PhaseActive); got != 1 {
		t.Fatalf("post-retention active = %d, want 1", got)
	}
	if len(keys) != 1 {
		t.Fatalf("JWKS should carry only the active key after retirement, got %d entries", len(keys))
	}
}

// invalidateCache forces the next access to reconcile instead of serving the
// cached snapshot; used by tests that advance the injected clock.
func (m *Manager) invalidateCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheExpiry = time.Time{}
}

func TestManagerConfigValidation(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		mutate    func(*Config)
		provider  dp.DataProtectionProvider
		wantError bool
	}{
		"disabled is always valid": {
			mutate:    func(c *Config) { c.Enabled = false },
			provider:  reversibleProvider{},
			wantError: false,
		},
		"empty allowed algorithms": {
			mutate:    func(c *Config) { c.AllowedAlgorithms = nil },
			provider:  reversibleProvider{},
			wantError: true,
		},
		"default algorithm not in allowed": {
			mutate:    func(c *Config) { c.DefaultAlgorithm = AlgRS512 },
			provider:  reversibleProvider{},
			wantError: true,
		},
		"unsupported algorithm": {
			mutate:    func(c *Config) { c.AllowedAlgorithms = []string{"HS256"}; c.DefaultAlgorithm = "HS256" },
			provider:  reversibleProvider{},
			wantError: true,
		},
		"lead time not shorter than rotation": {
			mutate:    func(c *Config) { c.ActivationLeadTime = c.RotationInterval },
			provider:  reversibleProvider{},
			wantError: true,
		},
		"negative rotation interval": {
			mutate:    func(c *Config) { c.RotationInterval = -time.Hour },
			provider:  reversibleProvider{},
			wantError: true,
		},
		"negative activation lead time": {
			mutate:    func(c *Config) { c.ActivationLeadTime = -time.Minute },
			provider:  reversibleProvider{},
			wantError: true,
		},
		"negative retention duration": {
			mutate:    func(c *Config) { c.RetentionDuration = -time.Minute },
			provider:  reversibleProvider{},
			wantError: true,
		},
		"negative cache ttl": {
			mutate:    func(c *Config) { c.CacheTTL = -time.Second },
			provider:  reversibleProvider{},
			wantError: true,
		},
		"negative clock skew": {
			mutate:    func(c *Config) { c.ClockSkew = -time.Second },
			provider:  reversibleProvider{},
			wantError: true,
		},
		"protector unavailable": {
			mutate:    func(c *Config) {},
			provider:  nil,
			wantError: true,
		},
		"valid enabled config": {
			mutate:    func(c *Config) {},
			provider:  reversibleProvider{},
			wantError: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := enabledConfig()
			tc.mutate(&cfg)
			store := NewMemoryRecordStore()
			m := NewManager(cfg, store, tc.provider, newFakeClock(), rand.Reader, nil)
			_, err := m.SigningCandidates()
			if tc.wantError && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if err != nil {
				records, listErr := store.List()
				if listErr != nil {
					t.Fatalf("list records: %v", listErr)
				}
				if len(records) != 0 {
					t.Fatalf("rejected configuration produced %d key record(s), want 0", len(records))
				}
			}
		})
	}
}

func TestManagerDisabledProducesNoMaterial(t *testing.T) {
	t.Parallel()

	cfg := enabledConfig()
	cfg.Enabled = false
	m := newTestManager(t, cfg, nil, newFakeClock())

	signing, err := m.SigningCandidates()
	if err != nil {
		t.Fatalf("signing candidates: %v", err)
	}
	if len(signing) != 0 {
		t.Fatalf("disabled manager returned %d signing candidates, want 0", len(signing))
	}
	keys, err := m.ValidationKeys()
	if err != nil {
		t.Fatalf("validation keys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("disabled manager returned %d validation keys, want 0", len(keys))
	}
}

func TestManagerAutoCreateDisabledFailsClosed(t *testing.T) {
	t.Parallel()

	cfg := enabledConfig()
	cfg.AutoCreate = false
	m := newTestManager(t, cfg, nil, newFakeClock())

	if _, err := m.SigningCandidates(); err == nil {
		t.Fatal("expected startup error when auto-create is disabled and no key exists")
	}
}

func TestManagerCacheReuseWithinTTL(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	m := newTestManager(t, enabledConfig(), store, clock)

	first, err := m.SigningCandidates()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	// Within the TTL the snapshot is reused and reconcile does not run again.
	second, err := m.SigningCandidates()
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first[0].Credential.Kid != second[0].Credential.Kid {
		t.Fatal("cached snapshot returned a different key within TTL")
	}
	if got := countPhase(t, store, PhaseActive); got != 1 {
		t.Fatalf("cache reuse created extra keys: active = %d", got)
	}
}

// failingStore fails List after a set number of successful calls to simulate a
// storage disruption.
type failingStore struct {
	inner      RecordStore
	mu         sync.Mutex
	calls      int
	failAfter  int
	failActive bool
}

func (s *failingStore) List() ([]*Record, error) {
	s.mu.Lock()
	s.calls++
	fail := s.failActive && s.calls > s.failAfter
	s.mu.Unlock()
	if fail {
		return nil, ErrConfiguration
	}
	return s.inner.List()
}
func (s *failingStore) Get(h string) (*Record, error)             { return s.inner.Get(h) }
func (s *failingStore) Create(r *Record) error                    { return s.inner.Create(r) }
func (s *failingStore) Update(r *Record, v uint64) error          { return s.inner.Update(r, v) }
func (s *failingStore) Delete(h string) error                     { return s.inner.Delete(h) }
func (s *failingStore) breakNow()                                 { s.mu.Lock(); s.failActive = true; s.mu.Unlock() }

func TestManagerStorageDisruptionKeepsLastGoodSigningKey(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := &failingStore{inner: NewMemoryRecordStore(), failAfter: 0}
	m := newTestManager(t, enabledConfig(), store, clock)

	first, err := m.SigningCandidates()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	kid := first[0].Credential.Kid

	// Break storage and expire the cache; signing availability must win over
	// fail-closed by returning the last known good key.
	store.breakNow()
	clock.advance(2 * time.Minute)
	m.invalidateCache()
	again, err := m.SigningCandidates()
	if err != nil {
		t.Fatalf("signing during disruption: %v", err)
	}
	if len(again) != 1 || again[0].Credential.Kid != kid {
		t.Fatal("storage disruption did not preserve the last good signing key")
	}

	// Validation fails closed once the cache TTL has expired.
	if _, err := m.ValidationKeys(); err == nil {
		t.Fatal("validation should fail closed after TTL during storage disruption")
	}
}

func TestManagerProtectedMaterialRecoveryFailure(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	// Pre-seed a record whose protected private material cannot be recovered.
	if err := store.Create(&Record{
		Handle:                   "seed",
		PublicID:                 "seed-kid",
		Purpose:                  PurposeTokenSigning,
		Algorithm:                AlgES256,
		Phase:                    PhaseActive,
		CreatedAt:                clock.Now(),
		NotAfter:                 clock.Now().Add(time.Hour),
		PublicMaterial:           validPublicMaterial(t),
		ProtectedPrivateMaterial: []byte("corrupt"),
		Format:                   protectionFormatV1,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cfg := enabledConfig()
	cfg.AutoCreate = false
	m := newTestManager(t, cfg, store, clock)

	if _, err := m.SigningCandidates(); err == nil {
		t.Fatal("expected signing error when private material cannot be recovered")
	}
	// The public material is intact, so validation still publishes the key.
	keys, err := m.ValidationKeys()
	if err != nil {
		t.Fatalf("validation keys: %v", err)
	}
	if len(keys) != 1 || keys[0].KeyId != "seed-kid" {
		t.Fatalf("validation should still publish public material, got %d keys", len(keys))
	}
}

func TestManagerRepeatedReconcileIsIdempotent(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	m := newTestManager(t, enabledConfig(), store, clock)

	for i := 0; i < 8; i++ {
		if _, err := m.SigningCandidates(); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		m.invalidateCache()
	}
	if got := countPhase(t, store, PhaseActive); got != 1 {
		t.Fatalf("idempotent reconcile active = %d, want 1", got)
	}
	records, _ := store.List()
	if len(records) != 1 {
		t.Fatalf("idempotent reconcile record count = %d, want 1", len(records))
	}
}

func TestManagerConcurrentInstancesConverge(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	cfg := enabledConfig()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := NewManager(cfg, store, reversibleProvider{}, clock, rand.Reader, nil)
			for j := 0; j < 5; j++ {
				_, _ = m.SigningCandidates()
			}
		}()
	}
	wg.Wait()

	// A final settling pass demotes any surplus active keys to a single active.
	settle := NewManager(cfg, store, reversibleProvider{}, clock, rand.Reader, nil)
	for i := 0; i < 4; i++ {
		if _, err := settle.SigningCandidates(); err != nil {
			t.Fatalf("settle: %v", err)
		}
		settle.invalidateCache()
	}
	if got := countPhase(t, store, PhaseActive); got != 1 {
		t.Fatalf("after convergence active = %d, want 1", got)
	}
}

// identityProvider returns bytes unchanged, standing in for a protector that
// applies no real protection.
type identityProvider struct{}

func (identityProvider) Create(string) dp.DataProtector { return identityProtector{} }

type identityProtector struct{}

func (identityProtector) Protect(data []byte) []byte { return append([]byte(nil), data...) }

func (identityProtector) Unprotect(data []byte) ([]byte, error) {
	return append([]byte(nil), data...), nil
}

func TestManagerCandidatePublishedBeforeActivation(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	cfg := enabledConfig()
	m := newTestManager(t, cfg, store, clock)

	if _, err := m.SigningCandidates(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	// Reach the rotation warm-up point so a candidate is created.
	clock.advance(cfg.RotationInterval - cfg.ActivationLeadTime + time.Second)
	m.invalidateCache()
	signing, err := m.SigningCandidates()
	if err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	if len(signing) != 1 {
		t.Fatalf("signing candidates = %d, want 1 (candidate must not sign yet)", len(signing))
	}

	// The warming candidate must already be resolvable through JWKS so verifier
	// caches observe its kid before it ever signs.
	keys, err := m.ValidationKeys()
	if err != nil {
		t.Fatalf("validation keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("validation keys = %d, want 2 (active + warming candidate)", len(keys))
	}
	kids := map[string]bool{}
	for _, k := range keys {
		kids[k.KeyId] = true
	}
	if !kids[signing[0].Credential.Kid] {
		t.Fatal("active kid missing from JWKS output")
	}
	if got := countPhase(t, store, PhaseCandidate); got != 1 {
		t.Fatalf("candidate count = %d, want 1", got)
	}
}

func TestManagerActivePublicMaterialFailureFailsValidationClosed(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	if err := store.Create(&Record{
		Handle:                   "seed",
		PublicID:                 "seed-kid",
		Purpose:                  PurposeTokenSigning,
		Algorithm:                AlgES256,
		Phase:                    PhaseActive,
		CreatedAt:                clock.Now(),
		NotAfter:                 clock.Now().Add(time.Hour),
		PublicMaterial:           []byte("garbage"),
		ProtectedPrivateMaterial: []byte("corrupt"),
		Format:                   protectionFormatV1,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cfg := enabledConfig()
	cfg.AutoCreate = false
	m := newTestManager(t, cfg, store, clock)

	// An active key whose public material cannot be serialized must fail the
	// whole validation set: its kid vanishing silently from JWKS would break
	// verification of everything it signs.
	if _, err := m.ValidationKeys(); err == nil {
		t.Fatal("expected validation error when an active key's public material is unusable")
	}
	if _, err := m.ExportValidationMaterial(); err == nil {
		t.Fatal("expected export error when an active key's public material is unusable")
	}
}

func TestManagerIdentityProtectorFailsClosed(t *testing.T) {
	t.Parallel()

	m := NewManager(enabledConfig(), NewMemoryRecordStore(), identityProvider{}, newFakeClock(), rand.Reader, nil)
	if _, err := m.SigningCandidates(); err == nil {
		t.Fatal("expected protector-unavailable error for an identity protector")
	}
}

func TestManagerOrphanCandidateRetiresDirectly(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	cfg := enabledConfig()
	m := newTestManager(t, cfg, store, clock)

	if _, err := m.SigningCandidates(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	// Seed a stale candidate that can never activate: created long before the
	// current active key, with a NotBefore still in the future.
	if err := store.Create(&Record{
		Handle:                   "stale",
		PublicID:                 "stale-kid",
		Purpose:                  PurposeTokenSigning,
		Algorithm:                AlgES256,
		Phase:                    PhaseCandidate,
		CreatedAt:                clock.Now().Add(-3 * time.Hour),
		NotBefore:                clock.Now().Add(time.Hour),
		NotAfter:                 clock.Now().Add(2 * time.Hour),
		PublicMaterial:           validPublicMaterial(t),
		ProtectedPrivateMaterial: []byte("protected:x"),
		Format:                   protectionFormatV1,
	}); err != nil {
		t.Fatalf("seed candidate: %v", err)
	}

	m.invalidateCache()
	if _, err := m.SigningCandidates(); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// The orphan never signed, so it retires directly instead of spending a
	// retention window in JWKS.
	if got := countPhase(t, store, PhaseRetired); got != 1 {
		t.Fatalf("retired count = %d, want 1", got)
	}
	if got := countPhase(t, store, PhaseCandidate); got != 0 {
		t.Fatalf("candidate count = %d, want 0", got)
	}
}

func TestManagerNilSeamsDoNotPanic(t *testing.T) {
	t.Parallel()

	m := NewManager(Config{}, nil, nil, nil, nil, nil)
	signing, err := m.SigningCandidates()
	if err != nil {
		t.Fatalf("disabled manager with nil seams: %v", err)
	}
	if len(signing) != 0 {
		t.Fatalf("disabled manager returned %d candidates, want 0", len(signing))
	}
}

func TestManagerExpiredActiveAutoCreatesReplacement(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	cfg := enabledConfig()

	// Seed the store with a single signing key whose signing window has already
	// closed, and no warming candidate behind it.
	const staleKid = "expired-active-kid"
	if err := store.Create(&Record{
		Handle:                   "expired",
		PublicID:                 staleKid,
		Purpose:                  PurposeTokenSigning,
		Algorithm:                AlgES256,
		Phase:                    PhaseActive,
		CreatedAt:                clock.Now().Add(-2 * time.Hour),
		NotAfter:                 clock.Now().Add(-time.Hour),
		PublicMaterial:           validPublicMaterial(t),
		ProtectedPrivateMaterial: []byte("protected:x"),
		Format:                   protectionFormatV1,
	}); err != nil {
		t.Fatalf("seed expired active: %v", err)
	}

	m := newTestManager(t, cfg, store, clock)

	signing, err := m.SigningCandidates()
	if err != nil {
		t.Fatalf("signing candidates: %v", err)
	}
	// Signing does not break: a fresh active key is available to sign.
	if len(signing) != 1 {
		t.Fatalf("signing candidate count = %d, want 1", len(signing))
	}
	if signing[0].Credential.Kid == staleKid {
		t.Fatal("replacement signing key must not reuse the expired key id")
	}
	// The expired key moves into retention; exactly one fresh active key exists.
	if got := countPhase(t, store, PhaseActive); got != 1 {
		t.Fatalf("active key count = %d, want 1", got)
	}
	if got := countPhase(t, store, PhaseRetained); got != 1 {
		t.Fatalf("retained key count = %d, want 1", got)
	}
	// The retained key is the original expired one, preserving verifiability of
	// tokens it already signed.
	records, err := store.List()
	if err != nil {
		t.Fatalf("list records: %v", err)
	}
	for _, r := range records {
		if r.Phase == PhaseRetained && r.PublicID != staleKid {
			t.Fatalf("retained key id = %q, want the expired key %q", r.PublicID, staleKid)
		}
		if r.Phase == PhaseActive && r.PublicID == staleKid {
			t.Fatal("expired key must not remain active")
		}
	}
}

func TestManagerSnapshotExpiresAfterCacheTTL(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	store := NewMemoryRecordStore()
	cfg := enabledConfig() // CacheTTL = 1m, ClockSkew = 1m.
	m := newTestManager(t, cfg, store, clock)

	// Build the initial snapshot; its validation set carries the one active key.
	if _, err := m.SigningCandidates(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	initial, err := m.ValidationKeys()
	if err != nil {
		t.Fatalf("initial validation keys: %v", err)
	}
	if len(initial) != 1 {
		t.Fatalf("initial validation key count = %d, want 1", len(initial))
	}

	// A second publishable key appears in the store after the snapshot was built.
	if err := store.Create(&Record{
		Handle:                   "arrived",
		PublicID:                 "arrived-kid",
		Purpose:                  PurposeTokenSigning,
		Algorithm:                AlgES256,
		Phase:                    PhaseRetained,
		CreatedAt:                clock.Now().Add(-time.Hour),
		NotBefore:                clock.Now().Add(-time.Hour),
		NotAfter:                 clock.Now().Add(-30 * time.Minute),
		RetainUntil:              clock.Now().Add(time.Hour),
		PublicMaterial:           validPublicMaterial(t),
		ProtectedPrivateMaterial: []byte("protected:x"),
		Format:                   protectionFormatV1,
	}); err != nil {
		t.Fatalf("inject record: %v", err)
	}

	// Advancing less than the cache TTL keeps serving the cached snapshot, so the
	// injected record is not yet reflected.
	clock.advance(cfg.CacheTTL - 30*time.Second)
	within, err := m.ValidationKeys()
	if err != nil {
		t.Fatalf("within-ttl validation keys: %v", err)
	}
	if len(within) != 1 {
		t.Fatalf("within-ttl validation key count = %d, want 1 (snapshot reused)", len(within))
	}

	// Advancing past the cache TTL retires the snapshot: the next access
	// reconciles and re-reads the store, so the injected record now shows up.
	clock.advance(cfg.CacheTTL)
	after, err := m.ValidationKeys()
	if err != nil {
		t.Fatalf("post-ttl validation keys: %v", err)
	}
	if len(after) != 2 {
		t.Fatalf("post-ttl validation key count = %d, want 2 (snapshot expired and store re-read)", len(after))
	}
}

func validPublicMaterial(t *testing.T) []byte {
	t.Helper()
	gen, err := generateKey(AlgES256, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return gen.publicDER
}

// ensure the rsa profile stays referenced so a future edit does not silently
// drop RSA support from the registry.
var _ = rsa.PublicKey{}
