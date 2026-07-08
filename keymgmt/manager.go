// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmt

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	core_models "github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/tokens"
)

// Conservative zero-value defaults applied when the host leaves a field unset.
const (
	defaultRotationInterval  = 90 * 24 * time.Hour
	defaultRetentionDuration = 14 * 24 * time.Hour
	defaultCacheTTL          = 5 * time.Minute
	defaultClockSkew         = 5 * time.Minute
	maxReconcileSteps        = 16
)

// Config is the resolved manager configuration. It is derived from the host
// options in the composition root; zero-valued durations receive conservative
// defaults before the manager runs.
type Config struct {
	Enabled              bool
	AutoCreate           bool
	RotationInterval     time.Duration
	ActivationLeadTime   time.Duration
	RetentionDuration    time.Duration
	AllowedAlgorithms    []string
	DefaultAlgorithm     string
	CacheTTL             time.Duration
	ClockSkew            time.Duration
	AllowMultipleActive  bool
	TokenLifetimeCeiling time.Duration
}

// SigningCandidate is one active, in-window key whose private material has been
// recovered, ready for signing selection by the consumer surface.
type SigningCandidate struct {
	Credential *tokens.SigningCredentials
	Priority   int
	NotBefore  time.Time
	NotAfter   time.Time
	CreatedAt  time.Time
}

// Manager maintains the key lifecycle, rotation and cached snapshots. It is
// inert when disabled. When enabled it is the exclusive source of signing
// credentials and contributes its public keys to JWKS output.
type Manager struct {
	cfg       Config
	store     RecordStore
	protector *keyProtector
	clock     Clock
	entropy   Entropy
	logger    *slog.Logger

	mu          sync.Mutex
	configErr   error
	configOnce  bool
	snapshot    *snapshot
	cacheExpiry time.Time
	lastGood    []SigningCandidate
}

type snapshot struct {
	signing    []SigningCandidate
	validation []*core_models.SecurityKeyInfo
}

// NewManager builds a manager from resolved configuration and injected seams.
// It resolves zero-value defaults but defers validation and the first key
// bootstrap until the first signing or validation access, so an assembled but
// unused manager never performs cryptographic work.
func NewManager(cfg Config, store RecordStore, provider dp.DataProtectionProvider, clock Clock, entropy Entropy, logger *slog.Logger) *Manager {
	return &Manager{
		cfg:       resolveDefaults(cfg),
		store:     store,
		protector: newKeyProtector(provider),
		clock:     clock,
		entropy:   entropy,
		logger:    logger,
	}
}

// resolveDefaults fills conservative defaults for zero-valued fields.
func resolveDefaults(cfg Config) Config {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = defaultCacheTTL
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = defaultClockSkew
	}
	if cfg.RotationInterval == 0 {
		cfg.RotationInterval = defaultRotationInterval
	}
	if cfg.RetentionDuration == 0 {
		cfg.RetentionDuration = defaultRetentionDuration
	}
	if cfg.ActivationLeadTime == 0 {
		cfg.ActivationLeadTime = cfg.CacheTTL
	}
	if len(cfg.AllowedAlgorithms) > 0 && cfg.DefaultAlgorithm == "" {
		cfg.DefaultAlgorithm = cfg.AllowedAlgorithms[0]
	}
	return cfg
}

// Enabled reports whether the manager provides signing material.
func (m *Manager) Enabled() bool { return m.cfg.Enabled }

// AllowedAlgorithms returns the configured allowed algorithm set used to
// constrain signing selection when the manager is enabled.
func (m *Manager) AllowedAlgorithms() []string {
	return append([]string(nil), m.cfg.AllowedAlgorithms...)
}

// validateConfig enforces the startup constraints. It runs once; the result is
// cached because configuration cannot change after assembly.
func (m *Manager) validateConfig() error {
	if m.configOnce {
		return m.configErr
	}
	m.configOnce = true
	m.configErr = m.checkConfig()
	return m.configErr
}

func (m *Manager) checkConfig() error {
	if !m.cfg.Enabled {
		return nil
	}
	if len(m.cfg.AllowedAlgorithms) == 0 {
		return fmt.Errorf("%w: enabled manager requires at least one allowed algorithm", ErrConfiguration)
	}
	allowed := map[string]bool{}
	for _, alg := range m.cfg.AllowedAlgorithms {
		if !isSupportedAlgorithm(alg) {
			return fmt.Errorf("%w: unsupported allowed algorithm %q", ErrConfiguration, alg)
		}
		allowed[alg] = true
	}
	if !allowed[m.cfg.DefaultAlgorithm] {
		return fmt.Errorf("%w: default algorithm %q not in allowed set", ErrConfiguration, m.cfg.DefaultAlgorithm)
	}
	if !m.protector.available() {
		return ErrProtectorUnavailable
	}
	for name, d := range map[string]time.Duration{
		"RotationInterval":   m.cfg.RotationInterval,
		"ActivationLeadTime": m.cfg.ActivationLeadTime,
		"RetentionDuration":  m.cfg.RetentionDuration,
		"CacheTTL":           m.cfg.CacheTTL,
		"ClockSkew":          m.cfg.ClockSkew,
	} {
		if d < 0 {
			return fmt.Errorf("%w: %s must not be negative", ErrConfiguration, name)
		}
	}
	if m.cfg.RotationInterval <= 0 {
		return fmt.Errorf("%w: RotationInterval must be positive", ErrConfiguration)
	}
	if m.cfg.ActivationLeadTime >= m.cfg.RotationInterval {
		return fmt.Errorf("%w: ActivationLeadTime must be shorter than RotationInterval", ErrConfiguration)
	}
	// Signing-gap and retention adequacy are warnings, not startup failures.
	if m.cfg.TokenLifetimeCeiling > 0 && m.cfg.RetentionDuration < m.cfg.TokenLifetimeCeiling+m.cfg.ClockSkew {
		m.warn("RetentionDuration may be shorter than token lifetime plus clock skew",
			"retention", m.cfg.RetentionDuration, "ceiling", m.cfg.TokenLifetimeCeiling)
	}
	return nil
}

// SigningCandidates returns the active, in-window signing candidates. Storage
// disruption falls back to the last known good candidates so signing stays
// available, which takes priority over fail-closed.
func (m *Manager) SigningCandidates() ([]SigningCandidate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap, err := m.currentSnapshot()
	if err != nil {
		if len(m.lastGood) > 0 {
			return cloneCandidates(m.lastGood), nil
		}
		return nil, err
	}
	if len(snap.signing) == 0 && m.cfg.Enabled {
		if len(m.lastGood) > 0 {
			return cloneCandidates(m.lastGood), nil
		}
		if !m.cfg.AutoCreate {
			return nil, fmt.Errorf("%w: automatic creation disabled and no active key", ErrNoSigningKey)
		}
		return nil, ErrNoSigningKey
	}
	return cloneCandidates(snap.signing), nil
}

// ValidationKeys returns the public key material for active and retained keys.
// Within the cache TTL a storage read failure returns the last good snapshot;
// after the TTL it fails closed.
func (m *Manager) ValidationKeys() ([]*core_models.SecurityKeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap, err := m.currentSnapshot()
	if err != nil {
		if m.snapshot != nil && m.clock.Now().Before(m.cacheExpiry) {
			return cloneKeyInfos(m.snapshot.validation), nil
		}
		return nil, err
	}
	return cloneKeyInfos(snap.validation), nil
}

// ExportValidationMaterial lists the public material of currently active and
// retained keys without gating on Enabled or running rotation. It supports a
// host draining auto-managed keys into its own validation stores when disabling
// the manager, so already-issued tokens keep resolving through JWKS.
func (m *Manager) ExportValidationMaterial() ([]*core_models.SecurityKeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	records, err := m.store.List()
	if err != nil {
		return nil, err
	}
	return m.buildValidation(records, m.clock.Now()), nil
}

// currentSnapshot returns a fresh snapshot, reconciling the lifecycle when the
// cache is cold or expired. Callers hold m.mu.
func (m *Manager) currentSnapshot() (*snapshot, error) {
	if err := m.validateConfig(); err != nil {
		return nil, err
	}
	if !m.cfg.Enabled {
		return &snapshot{}, nil
	}
	now := m.clock.Now()
	if m.snapshot != nil && now.Before(m.cacheExpiry) {
		return m.snapshot, nil
	}
	if err := m.reconcile(now); err != nil {
		return nil, err
	}
	records, err := m.store.List()
	if err != nil {
		return nil, err
	}
	snap := &snapshot{
		signing:    m.buildSigning(records, now),
		validation: m.buildValidation(records, now),
	}
	m.snapshot = snap
	m.cacheExpiry = now.Add(m.cfg.CacheTTL)
	if len(snap.signing) > 0 {
		m.lastGood = snap.signing
	}
	return snap, nil
}

// reconcile drives the lifecycle to convergence by applying one committed
// transition per iteration. Each transition is optimistic-concurrency guarded,
// so concurrent instances converge without producing duplicate keys.
func (m *Manager) reconcile(now time.Time) error {
	for i := 0; i < maxReconcileSteps; i++ {
		records, err := m.store.List()
		if err != nil {
			return err
		}
		mutated, err := m.reconcileStep(now, records)
		if err != nil {
			if errors.Is(err, ErrVersionConflict) || errors.Is(err, ErrDuplicateKey) {
				// Another instance advanced the state; re-read and continue.
				continue
			}
			return err
		}
		if !mutated {
			return nil
		}
	}
	return nil
}

// reconcileStep finds the single highest-priority actionable transition, commits
// it, and reports whether it mutated state.
func (m *Manager) reconcileStep(now time.Time, records []*Record) (bool, error) {
	// 1. Retire retained keys past their retention window.
	for _, r := range records {
		if r.Phase == PhaseRetained && !r.RetainUntil.IsZero() && !now.Before(r.RetainUntil) {
			next := copyRecord(r)
			next.Phase = PhaseRetired
			return true, m.store.Update(next, r.Version)
		}
	}
	// 2. Move expired active keys into retention.
	for _, r := range records {
		if r.Phase == PhaseActive && !r.NotAfter.IsZero() && !now.Before(r.NotAfter) {
			return true, m.retain(r, now)
		}
	}
	// 3. Activate a candidate whose warm-up and window are satisfied.
	for _, r := range records {
		if r.Phase == PhaseCandidate && m.candidateReady(r, now) {
			next := copyRecord(r)
			next.Phase = PhaseActive
			return true, m.store.Update(next, r.Version)
		}
	}
	// 4. Demote surplus active keys when multiple active is not allowed.
	if !m.cfg.AllowMultipleActive {
		if surplus := m.surplusActive(records); surplus != nil {
			return true, m.retain(surplus, now)
		}
	}
	// 5. Bootstrap the first active key directly when none can sign.
	if !m.hasActiveSignable(records, now) {
		if m.cfg.AutoCreate {
			return true, m.createKey(now, PhaseActive)
		}
		return false, nil
	}
	// 6. Isolate a stale orphan candidate that can no longer become active.
	for _, r := range records {
		if r.Phase == PhaseCandidate && m.orphanCandidate(r, now) {
			return true, m.retain(r, now)
		}
	}
	// 7. Warm up the next rotation candidate ahead of active expiry.
	if m.shouldRotate(records, now) {
		return true, m.createKey(now, PhaseCandidate)
	}
	return false, nil
}

// candidateReady reports whether a candidate has reached its NotBefore and has
// been published long enough to satisfy the pre-publish constraint.
func (m *Manager) candidateReady(r *Record, now time.Time) bool {
	if !r.NotBefore.IsZero() && now.Before(r.NotBefore) {
		return false
	}
	lead := m.cfg.ActivationLeadTime
	if m.cfg.CacheTTL > lead {
		lead = m.cfg.CacheTTL
	}
	return !now.Before(r.CreatedAt.Add(lead))
}

// orphanCandidate reports whether a candidate is stale and can no longer be
// activated because a fresh active key already exists.
func (m *Manager) orphanCandidate(r *Record, now time.Time) bool {
	grace := m.cfg.ActivationLeadTime
	if m.cfg.CacheTTL > grace {
		grace = m.cfg.CacheTTL
	}
	if now.Before(r.CreatedAt.Add(2 * grace)) {
		return false
	}
	// Only isolate a stale candidate once a fresher active key already covers
	// signing, so the orphan is not needed.
	return m.hasFreshActive(r, now)
}

// hasFreshActive reports whether some active key newer than the candidate exists.
func (m *Manager) hasFreshActive(candidate *Record, now time.Time) bool {
	records, err := m.store.List()
	if err != nil {
		return false
	}
	for _, r := range records {
		if r.Phase == PhaseActive && r.CreatedAt.After(candidate.CreatedAt) && r.withinSigningWindow(now) {
			return true
		}
	}
	return false
}

// surplusActive returns the lowest-ranked active key when more than one active
// key of the signing purpose exists, or nil.
func (m *Manager) surplusActive(records []*Record) *Record {
	var actives []*Record
	for _, r := range records {
		if r.Phase == PhaseActive && r.Purpose == PurposeTokenSigning {
			actives = append(actives, r)
		}
	}
	if len(actives) <= 1 {
		return nil
	}
	sort.SliceStable(actives, func(i, j int) bool {
		return lessPreferred(actives[i], actives[j])
	})
	// actives sorted best-first; the last is the least preferred to demote.
	return actives[len(actives)-1]
}

// retain transitions a key into the retained phase and computes its retirement
// deadline when unset.
func (m *Manager) retain(r *Record, now time.Time) error {
	next := copyRecord(r)
	next.Phase = PhaseRetained
	if next.RetainUntil.IsZero() {
		base := now
		if !next.NotAfter.IsZero() && next.NotAfter.After(base) {
			base = next.NotAfter
		}
		next.RetainUntil = base.Add(m.cfg.RetentionDuration)
	}
	return m.store.Update(next, r.Version)
}

// hasActiveSignable reports whether any active key can currently sign. When
// records is nil the store is read.
func (m *Manager) hasActiveSignable(records []*Record, now time.Time) bool {
	if records == nil {
		var err error
		records, err = m.store.List()
		if err != nil {
			return false
		}
	}
	for _, r := range records {
		if r.Phase == PhaseActive && r.withinSigningWindow(now) && m.recoverable(r) {
			return true
		}
	}
	return false
}

// shouldRotate reports whether an active key is aging and no candidate is warming
// up yet, so a replacement should be created. An acceptable existing candidate
// suppresses creating another.
func (m *Manager) shouldRotate(records []*Record, now time.Time) bool {
	var newestActive *Record
	for _, r := range records {
		if r.Phase == PhaseCandidate {
			return false
		}
		if r.Phase == PhaseActive && r.withinSigningWindow(now) {
			if newestActive == nil || r.CreatedAt.After(newestActive.CreatedAt) {
				newestActive = r
			}
		}
	}
	if newestActive == nil || newestActive.NotAfter.IsZero() {
		return false
	}
	return !now.Before(newestActive.NotAfter.Add(-m.cfg.ActivationLeadTime))
}

// createKey generates, protects and persists a new key in the given phase.
func (m *Manager) createKey(now time.Time, phase Phase) error {
	if !m.protector.available() {
		return ErrProtectorUnavailable
	}
	alg := m.cfg.DefaultAlgorithm
	gen, err := generateKey(alg, m.entropy)
	if err != nil {
		return err
	}
	protected, format, err := m.protector.protect(gen.privateDER)
	if err != nil {
		return err
	}
	handle, err := m.newHandle()
	if err != nil {
		return err
	}
	record := &Record{
		Handle:                   handle,
		PublicID:                 gen.publicID,
		Purpose:                  PurposeTokenSigning,
		Algorithm:                alg,
		Phase:                    phase,
		CreatedAt:                now,
		PublicMaterial:           gen.publicDER,
		ProtectedPrivateMaterial: protected,
		Format:                   format,
	}
	if phase == PhaseActive {
		record.NotAfter = now.Add(m.cfg.RotationInterval)
	} else {
		record.NotBefore = now.Add(m.cfg.ActivationLeadTime)
		record.NotAfter = record.NotBefore.Add(m.cfg.RotationInterval)
	}
	if err := validateWindow(record); err != nil {
		return err
	}
	return m.store.Create(record)
}

// recoverable reports whether a record's private material can be unprotected and
// parsed for its algorithm.
func (m *Manager) recoverable(r *Record) bool {
	_, err := m.signerFor(r)
	return err == nil
}

// signerFor recovers the private signer for a record.
func (m *Manager) signerFor(r *Record) (tokens.SecurityKey, error) {
	plain, err := m.protector.recover(r.ProtectedPrivateMaterial, r.Format)
	if err != nil {
		return nil, err
	}
	signer, err := recoverPrivateKey(r.Algorithm, plain)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// buildSigning produces signing candidates from active, in-window, recoverable
// records, sorted by the single selection rule.
func (m *Manager) buildSigning(records []*Record, now time.Time) []SigningCandidate {
	var out []SigningCandidate
	for _, r := range records {
		if r.Phase != PhaseActive || !r.withinSigningWindow(now) {
			continue
		}
		signer, err := m.signerFor(r)
		if err != nil {
			m.warn("active key private material not recoverable", "kid", r.PublicID, "err", err)
			continue
		}
		credential, err := tokens.NewSigningCredentials(signer, tokens.WithAlgorithm(r.Algorithm), tokens.WithKid(r.PublicID))
		if err != nil {
			continue
		}
		out = append(out, SigningCandidate{
			Credential: credential,
			Priority:   r.Priority,
			NotBefore:  r.NotBefore,
			NotAfter:   r.NotAfter,
			CreatedAt:  r.CreatedAt,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return lessPreferredCandidate(out[i], out[j])
	})
	return out
}

// buildValidation produces JWKS-facing public key material for active and
// retained keys within the publish window. An active key whose public material
// cannot be recovered fails the whole set; a retained key is omitted with a
// recorded warning.
func (m *Manager) buildValidation(records []*Record, now time.Time) []*core_models.SecurityKeyInfo {
	var out []*core_models.SecurityKeyInfo
	for _, r := range records {
		if r.Phase != PhaseActive && r.Phase != PhaseRetained {
			continue
		}
		if !r.withinPublishWindow(now, m.cfg.ClockSkew) {
			continue
		}
		pub, err := recoverPublicKey(r.PublicMaterial)
		if err != nil {
			if r.Phase == PhaseActive {
				m.warn("active key public material not serializable", "kid", r.PublicID, "err", err)
				// Active key must remain visible; surface as empty so the caller
				// treats the set as unavailable rather than silently dropping it.
				return nil
			}
			m.warn("omitting retained key with unusable public material", "kid", r.PublicID, "err", err)
			continue
		}
		out = append(out, &core_models.SecurityKeyInfo{
			Key:              pub,
			SigningAlgorithm: r.Algorithm,
			KeyId:            r.PublicID,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].KeyId < out[j].KeyId })
	return out
}

func (m *Manager) newHandle() (string, error) {
	buf := make([]byte, 16)
	if _, err := m.entropy.Read(buf); err != nil {
		return "", fmt.Errorf("generate key handle: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func (m *Manager) warn(msg string, args ...any) {
	if m.logger != nil {
		m.logger.Warn(msg, args...)
	}
}

// lessPreferred orders records best-first by the single selection rule.
func lessPreferred(a, b *Record) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if !a.NotBefore.Equal(b.NotBefore) {
		return a.NotBefore.After(b.NotBefore)
	}
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.After(b.CreatedAt)
	}
	return a.PublicID < b.PublicID
}

// lessPreferredCandidate applies the same ordering to signing candidates.
func lessPreferredCandidate(a, b SigningCandidate) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if !a.NotBefore.Equal(b.NotBefore) {
		return a.NotBefore.After(b.NotBefore)
	}
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.After(b.CreatedAt)
	}
	return a.Credential.Kid < b.Credential.Kid
}

func cloneCandidates(in []SigningCandidate) []SigningCandidate {
	return append([]SigningCandidate(nil), in...)
}

func cloneKeyInfos(in []*core_models.SecurityKeyInfo) []*core_models.SecurityKeyInfo {
	return append([]*core_models.SecurityKeyInfo(nil), in...)
}
