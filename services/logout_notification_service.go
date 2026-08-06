// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package services

import (
	"context"

	"github.com/gonewx/wicket/models/contexts"
)

// LogoutNotificationService Provides features for OIDC signout notifications.
type LogoutNotificationService interface {
	/// Builds the URLs needed for front-channel logout notification.
	GetFrontChannelLogoutNotificationsUrls(ctx context.Context, notification *contexts.LogoutNotificationContext) ([]string, error)

	/// Builds the http back-channel logout request data for the collection of clients.
	GetBackchannelLogoutNotifications(ctx context.Context, notification *contexts.LogoutNotificationContext) ([]*BackchannelLogoutRequest, error)
}

// BackchannelLogoutRequest Information necessary to make a back-channel logout request to a client.
type BackchannelLogoutRequest struct {
	/// Gets or sets the client identifier.
	ClientId string

	/// Gets or sets the subject identifier.
	SubjectId string

	/// Gets or sets the session identifier.
	SessionId string

	/// Gets or sets the back channel logout URI.
	LogoutUri string

	/// Gets a value indicating whether the session identifier is required.
	SessionIdRequired bool

	/// The issuer for the back-channel logout
	Issuer string
}
