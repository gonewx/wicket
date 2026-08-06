// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package memory

import (
	"context"

	core_models "github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/tokens"
)

// MemorySigningCredentialStore returns a configured signing credential.
// input: none -> behavior: read in-memory credential -> output: signing credential.
type MemorySigningCredentialStore struct {
	credential *tokens.SigningCredentials
}

func NewMemorySigningCredentialStore(credential *tokens.SigningCredentials) *MemorySigningCredentialStore {
	return &MemorySigningCredentialStore{credential: credential}
}

func (s *MemorySigningCredentialStore) GetSigningCredentials(ctx context.Context) (*tokens.SigningCredentials, error) {
	return s.credential, nil
}

// MemoryValidationKeysStore returns configured validation keys.
// input: none -> behavior: read in-memory key list -> output: validation keys.
type MemoryValidationKeysStore struct {
	keys []*core_models.SecurityKeyInfo
}

func NewMemoryValidationKeysStore(keys []*core_models.SecurityKeyInfo) *MemoryValidationKeysStore {
	return &MemoryValidationKeysStore{keys: keys}
}

func (s *MemoryValidationKeysStore) GetValidationKeys(ctx context.Context) ([]*core_models.SecurityKeyInfo, error) {
	return append([]*core_models.SecurityKeyInfo(nil), s.keys...), nil
}
