// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models/messages"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type MockConsentService struct {
	RequiresConsentResult bool

	ConsentSubject *claims.ClaimsPrincipal
	ConsentClient  *storage_models.Client
	ConsentScopes  []string
}

func NewMockConsentService() *MockConsentService {
	return &MockConsentService{}
}

func (s *MockConsentService) RequiresConsent(subject *claims.ClaimsPrincipal, client *storage_models.Client, parsedScopes []*validators_models.ParsedScopeValue) (bool, error) {
	return s.RequiresConsentResult, nil
}

func (s *MockConsentService) UpdateConsent(subject *claims.ClaimsPrincipal, client *storage_models.Client, parsedScopes []*validators_models.ParsedScopeValue) error {
	s.ConsentSubject = subject
	s.ConsentClient = client
	s.ConsentScopes = utils.Select(parsedScopes,
		func(x *validators_models.ParsedScopeValue) string {
			return x.RawValue
		})

	return nil
}

func (s *MockConsentService) GrantConsent(*messages.AuthorizationRequest, *messages.ConsentResponse, string) error {
	return nil
}

func (s *MockConsentService) DenyAuthorization(*messages.AuthorizationRequest, string) error {
	return nil
}
