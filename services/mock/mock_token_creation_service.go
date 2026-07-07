// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import storage_models "github.com/gonewx/wicket/storage/models"

type MockTokenCreationService struct {
	TokenResult string
	Token       *storage_models.Token
}

func NewMockTokenCreationService() *MockTokenCreationService {
	return &MockTokenCreationService{}
}

func (s *MockTokenCreationService) CreateToken(token *storage_models.Token) (string, error) {
	s.Token = token
	return s.TokenResult, nil
}
