// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models"
	"github.com/google/uuid"
)

type MockUserSession struct {
	Clients                        []string
	EnsureSessionIdCookieWasCalled bool
	RemoveSessionIdCookieWasCalled bool
	CreateSessionIdWasCalled       bool
	User                           *claims.ClaimsPrincipal
	SessionId                      string
	Properties                     *models.AuthenticationProperties

	items map[string]any
}

func NewMockUserSession() *MockUserSession {
	return &MockUserSession{
		Clients: []string{},
		items:   make(map[string]any, 0),
	}
}

func (s *MockUserSession) EnsureSessionIdCookie() error {
	s.EnsureSessionIdCookieWasCalled = true
	return nil
}

func (s *MockUserSession) RemoveSessionIdCookie() error {
	s.RemoveSessionIdCookieWasCalled = true
	return nil
}

func (s *MockUserSession) CreateSessionId(principal *claims.ClaimsPrincipal, properties *auth.Properties) (string, error) {
	s.CreateSessionIdWasCalled = true
	s.User = principal

	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	s.SessionId = id.String()
	return s.SessionId, nil
}

func (s *MockUserSession) GetSessionId() string {
	return s.SessionId
}

func (s *MockUserSession) GetClientList() ([]string, error) {
	return s.Clients, nil
}

func (s *MockUserSession) GetUser() *claims.ClaimsPrincipal {
	return s.User
}

func (s *MockUserSession) AddClientId(clientId string) error {
	s.Clients = append(s.Clients, clientId)
	return nil
}

func (s *MockUserSession) Item(key string) (any, bool) {
	return s.items, true
}

func (s *MockUserSession) SetItem(key string, item any) {
	s.items[key] = item
}
