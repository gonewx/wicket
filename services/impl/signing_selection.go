// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/gonewx/wicket/keymgmt"
	core_models "github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/tokens"
)

// KeyMaterialService selects signing credentials and aggregates validation keys.
// When the automatic key manager is enabled it is the exclusive source of
// signing material and host signing stores do not participate in selection; host
// validation stores continue to aggregate into JWKS output. When disabled the
// service falls back entirely to host-injected stores.
type KeyMaterialService struct {
	signingStores    []storage.SigningCredentialStore
	validationStores []storage.ValidationKeysStore
	manager          *keymgmt.Manager
	logger           *slog.Logger
}

func NewKeyMaterialService(
	signingStores []storage.SigningCredentialStore,
	validationStores []storage.ValidationKeysStore,
	manager *keymgmt.Manager,
	logger *slog.Logger,
) *KeyMaterialService {
	return &KeyMaterialService{
		signingStores:    signingStores,
		validationStores: validationStores,
		manager:          manager,
		logger:           logger,
	}
}

// signingChoice is a signing credential paired with the metadata needed to apply
// the single selection rule. Host credentials carry zero metadata and are
// treated as unconstrained, ties broken by public id.
type signingChoice struct {
	credential *tokens.SigningCredentials
	priority   int
	notBefore  time.Time
	notAfter   time.Time
	createdAt  time.Time
}

func (s *KeyMaterialService) autoEnabled() bool {
	return s.manager != nil && s.manager.Enabled()
}

// signingChoices returns the eligible signing credentials from the active
// source: the auto manager when enabled, otherwise host signing stores.
func (s *KeyMaterialService) signingChoices(ctx context.Context) ([]signingChoice, error) {
	if s.autoEnabled() {
		candidates, err := s.manager.SigningCandidates(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]signingChoice, 0, len(candidates))
		for _, c := range candidates {
			out = append(out, signingChoice{
				credential: c.Credential,
				priority:   c.Priority,
				notBefore:  c.NotBefore,
				notAfter:   c.NotAfter,
				createdAt:  c.CreatedAt,
			})
		}
		return out, nil
	}
	out := make([]signingChoice, 0, len(s.signingStores))
	for _, store := range s.signingStores {
		credential, err := store.GetSigningCredentials(ctx)
		if err != nil {
			return nil, err
		}
		if credential != nil {
			out = append(out, signingChoice{credential: credential})
		}
	}
	return out, nil
}

// GetSigningCredentials selects one signing credential by intersecting the
// requested algorithms with the configured allowed set and applying the single
// selection rule (priority, then newer NotBefore, then newer CreatedAt, then
// public id ascending).
func (s *KeyMaterialService) GetSigningCredentials(ctx context.Context, allowed []string) (*tokens.SigningCredentials, error) {
	choices, err := s.signingChoices(ctx)
	if err != nil {
		return nil, err
	}

	var configAllowed []string
	if s.autoEnabled() {
		configAllowed = s.manager.AllowedAlgorithms()
	}
	allowSet, unrestricted, emptyIntersection := resolveAllowedAlgorithms(allowed, configAllowed)
	if emptyIntersection {
		return nil, fmt.Errorf("no signing credential: requested algorithms do not overlap the allowed algorithm set")
	}

	filtered := make([]signingChoice, 0, len(choices))
	for _, c := range choices {
		if c.credential == nil {
			continue
		}
		if !unrestricted && !allowSet[c.credential.Algorithm] {
			continue
		}
		filtered = append(filtered, c)
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("no signing credential available for the requested algorithms")
	}

	sort.SliceStable(filtered, func(i, j int) bool { return lessPreferredChoice(filtered[i], filtered[j]) })
	return filtered[0].credential, nil
}

// GetAllSigningCredentials returns every currently signable credential from the
// active source.
func (s *KeyMaterialService) GetAllSigningCredentials(ctx context.Context) ([]*tokens.SigningCredentials, error) {
	choices, err := s.signingChoices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*tokens.SigningCredentials, 0, len(choices))
	for _, c := range choices {
		if c.credential != nil {
			out = append(out, c.credential)
		}
	}
	return out, nil
}

// GetValidationKeys aggregates auto-managed validation keys and host validation
// stores. Per-host-store read errors are isolated so one failing store does not
// hide the surviving keys; a duplicate public id keeps the auto-managed key and
// omits the later duplicate. A failure of the enabled automatic key set is not
// isolated: the kids currently signing could be missing from the output, and a
// JWKS without them breaks verification, so the error propagates. Host-store
// aggregation fails closed only when every source errored and no key survived.
func (s *KeyMaterialService) GetValidationKeys(ctx context.Context) ([]*core_models.SecurityKeyInfo, error) {
	out := make([]*core_models.SecurityKeyInfo, 0)
	seen := map[string]bool{}
	var firstErr error
	failed := false

	appendKey := func(key *core_models.SecurityKeyInfo) {
		if key == nil {
			return
		}
		if key.KeyId != "" {
			if seen[key.KeyId] {
				s.warn("omitting duplicate validation key id", "kid", key.KeyId)
				return
			}
			seen[key.KeyId] = true
		}
		out = append(out, key)
	}

	if s.autoEnabled() {
		keys, err := s.manager.ValidationKeys(ctx)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			appendKey(key)
		}
	}

	for _, store := range s.validationStores {
		keys, err := store.GetValidationKeys(ctx)
		if err != nil {
			failed = true
			if firstErr == nil {
				firstErr = err
			}
			s.warn("validation key store read failed", "err", err)
			continue
		}
		for _, key := range keys {
			appendKey(key)
		}
	}

	if len(out) == 0 && failed {
		return nil, firstErr
	}
	return out, nil
}

func (s *KeyMaterialService) warn(msg string, args ...any) {
	if s.logger != nil {
		s.logger.Warn(msg, args...)
	}
}

// resolveAllowedAlgorithms combines the caller's requested algorithms with the
// configured allowed set. An empty request defers to the configured set; an
// empty configured set (host-store mode) imposes no additional limit. A non-empty
// intersection that is empty signals an explicit error to the caller.
func resolveAllowedAlgorithms(requested, configAllowed []string) (set map[string]bool, unrestricted bool, emptyIntersection bool) {
	requestSet := toSet(requested)
	configSet := toSet(configAllowed)

	switch {
	case len(requestSet) == 0 && len(configSet) == 0:
		return nil, true, false
	case len(requestSet) == 0:
		return configSet, false, false
	case len(configSet) == 0:
		return requestSet, false, false
	default:
		intersection := map[string]bool{}
		for alg := range requestSet {
			if configSet[alg] {
				intersection[alg] = true
			}
		}
		if len(intersection) == 0 {
			return nil, false, true
		}
		return intersection, false, false
	}
}

func toSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]bool, len(values))
	for _, v := range values {
		if v != "" {
			set[v] = true
		}
	}
	return set
}

// lessPreferredChoice orders signing credentials best-first by the single
// selection rule.
func lessPreferredChoice(a, b signingChoice) bool {
	if a.priority != b.priority {
		return a.priority > b.priority
	}
	if !a.notBefore.Equal(b.notBefore) {
		return a.notBefore.After(b.notBefore)
	}
	if !a.createdAt.Equal(b.createdAt) {
		return a.createdAt.After(b.createdAt)
	}
	return a.credential.Kid < b.credential.Kid
}
