// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
)

type MockLogoutNotificationService struct {
	GetFrontChannelLogoutNotificationsUrlsCalled bool
	FrontChannelLogoutNotificationsUrls          []string

	SendBackchannelLogoutNotificationsCalled bool
	BackchannelLogoutRequests                []*services.BackchannelLogoutRequest
}

func NewMockLogoutNotificationService() *MockLogoutNotificationService {
	return &MockLogoutNotificationService{}
}

// / Builds the URLs needed for front-channel logout notification.
func (s *MockLogoutNotificationService) GetFrontChannelLogoutNotificationsUrls(ctx *contexts.LogoutNotificationContext) ([]string, error) {
	s.GetFrontChannelLogoutNotificationsUrlsCalled = true
	return s.FrontChannelLogoutNotificationsUrls, nil
}

// / Builds the http back-channel logout request data for the collection of clients.
func (s *MockLogoutNotificationService) GetBackchannelLogoutNotifications(ctx *contexts.LogoutNotificationContext) ([]*services.BackchannelLogoutRequest, error) {
	s.SendBackchannelLogoutNotificationsCalled = true
	return s.BackchannelLogoutRequests, nil
}
