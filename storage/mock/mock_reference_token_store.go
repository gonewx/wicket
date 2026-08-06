// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	"context"
	"fmt"

	"github.com/gonewx/wicket/storage/models"
)

type MockReferenceTokenStore struct {
}

func NewMockReferenceTokenStore() *MockReferenceTokenStore {
	return &MockReferenceTokenStore{}
}

func (m *MockReferenceTokenStore) StoreReferenceToken(ctx context.Context, token *models.Token) (string, error) {
	return "", fmt.Errorf("Not implemented")
}

func (m *MockReferenceTokenStore) GetReferenceToken(ctx context.Context, handle string) (*models.Token, error) {
	return nil, fmt.Errorf("Not implemented")
}

func (m *MockReferenceTokenStore) RemoveReferenceToken(ctx context.Context, handle string) error {
	return fmt.Errorf("Not implemented")
}

func (m *MockReferenceTokenStore) RemoveReferenceTokens(ctx context.Context, subjectId, clientId string) error {
	return fmt.Errorf("Not implemented")
}
