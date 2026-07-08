// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

import (
	"time"

	"github.com/gonewx/wicket/claims"
)

type BackchannelAuthenticationRequestStatus string

const (
	BackchannelAuthenticationRequestStatusPending  BackchannelAuthenticationRequestStatus = "pending"
	BackchannelAuthenticationRequestStatusApproved BackchannelAuthenticationRequestStatus = "approved"
	BackchannelAuthenticationRequestStatusDenied   BackchannelAuthenticationRequestStatus = "denied"
	BackchannelAuthenticationRequestStatusConsumed BackchannelAuthenticationRequestStatus = "consumed"
)

type BackchannelAuthenticationRequest struct {
	RequestId                  string
	ClientId                   string
	SubjectId                  string
	Subject                    *claims.ClaimsPrincipal
	RequestedScopes            []string
	RequestedResourceGaps      []string
	DeliveryMode               string
	BindingMessage             string
	UserCode                   string
	RequestedExpiry            int
	RequestObject              string
	Status                     BackchannelAuthenticationRequestStatus
	CreationTime               time.Time
	ExpirationTime             time.Time
	PollInterval               int
	LastPollTime               *time.Time
	ClientNotificationToken    string
	ClientNotificationEndpoint string
}
