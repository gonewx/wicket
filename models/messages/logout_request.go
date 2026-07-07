// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package messages

import (
	"net/url"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// Models the validated singout context.
type LogoutMessage struct {

	// Gets or sets the client identifier.
	ClientId string

	// Gets or sets the client name.
	ClientName string

	// Gets or sets the post logout redirect URI.
	PostLogoutRedirectUri string

	// Gets or sets the subject identifier for the user at logout time.
	SubjectId string

	// Gets or sets the session identifier for the user at logout time.
	SessionId string

	//  Ids of clients known to have an authentication session for user at end session time
	ClientIds []string

	// The UI locales.
	UiLocales string

	// Gets the entire parameter collection.
	Parameters map[string][]string
}

// Initializes a new instance of the <see cref="LogoutMessage"/> class.
// <param name="request">The request.</param>
func NewLogoutMessage(request *validators_models.ValidatedEndSessionRequest) *LogoutMessage {
	m := &LogoutMessage{}
	if request == nil {
		return m
	}

	if request.Raw != nil {
		m.Parameters = request.Raw
	}

	// optimize params sent to logout page, since we'd like to send them in URL (not as cookie)
	delete(m.Parameters, gois.EndSessionRequestIdTokenHint)
	delete(m.Parameters, gois.EndSessionRequestPostLogoutRedirectUri)
	delete(m.Parameters, gois.EndSessionRequestState)
	delete(m.Parameters, gois.AuthorizeRequestUiLocales)

	if request.Client != nil {
		m.ClientId = request.Client.ClientId
		m.ClientName = request.Client.ClientName
	}

	m.SessionId = request.SessionId
	m.ClientIds = request.ClientIds
	m.UiLocales = request.UiLocales

	if request.PostLogOutUri != "" {
		m.PostLogoutRedirectUri = request.PostLogOutUri
		if request.State != "" {
			m.PostLogoutRedirectUri = utils.AddQuery(m.PostLogoutRedirectUri, gois.EndSessionRequestState, request.State)
		}
	}

	return m
}

// ContainsPayload  Flag to indicate if the payload contains useful information or not to avoid serialization.
func (m *LogoutMessage) ContainsPayload() bool {
	return strings.TrimSpace(m.ClientId) != "" || len(m.ClientIds) > 0
}

// LogoutRequest Models the request from a client to sign the user out.
type LogoutRequest struct {

	// Gets or sets the client identifier.
	ClientId string

	// Gets or sets the client name.
	ClientName string

	// Gets or sets the post logout redirect URI.
	PostLogoutRedirectUri string

	// Gets or sets the subject identifier for the user at logout time.
	SubjectId string

	// Gets or sets the session identifier for the user at logout time.
	SessionId string

	//  Ids of clients known to have an authentication session for user at end session time
	ClientIds []string

	// The UI locales.
	UiLocales string

	// Gets the entire parameter collection.
	Parameters url.Values

	// Gets or sets the sign out iframe URL.
	// The sign out iframe URL.
	SignOutIFrameUrl string
}

// Initializes a new instance of the <see cref="LogoutRequest"/> class.
func NewLogoutRequest(iframeUrl string, message *LogoutMessage) *LogoutRequest {
	r := &LogoutRequest{}

	if message != nil {
		r.ClientId = message.ClientId
		r.ClientName = message.ClientName
		r.PostLogoutRedirectUri = message.PostLogoutRedirectUri
		r.SubjectId = message.SubjectId
		r.SessionId = message.SessionId
		r.ClientIds = message.ClientIds
		r.UiLocales = message.UiLocales
		r.Parameters = message.Parameters
	}

	r.SignOutIFrameUrl = iframeUrl

	return r
}

// ShowSignoutPrompt Gets or sets a value indicating whether the user should be prompted for signout.
//
//	<c>true</c> if the signout prompt should be shown; otherwise, <c>false</c>.
func (r *LogoutRequest) ShowSignoutPrompt() bool {
	return strings.TrimSpace(r.ClientId) == ""
}
