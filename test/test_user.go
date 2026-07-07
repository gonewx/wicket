// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package test

import "github.com/gonewx/wicket/claims"

// TestUser In-memory user object for testing. Not intended for modeling users in production.
type TestUser struct {
	SubjectId string

	Username string

	Password string

	ProviderName string

	ProviderSubjectId string

	IsActive bool

	Claims []*claims.Claim
}

func NewTestUser() *TestUser {
	return &TestUser{
		IsActive: true,
		Claims:   make([]*claims.Claim, 0),
	}
}
