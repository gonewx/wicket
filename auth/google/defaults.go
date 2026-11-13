// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package google

import "github.com/gonewx/wicket"

const (
	// The default value used for Options.AuthenticationScheme
	AuthenticationScheme = wicket.GoogleAuthenticationScheme

	// The default display name for Google authentication.
	DisplayName = "Google"

	// The default endpoint used to perform Google authentication.
	// For more details about this endpoint, see https://developers.google.com/identity/protocols/oauth2/web-server#httprest
	AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"

	// The OAuth endpoint used to exchange access tokens.
	TokenEndpoint = "https://oauth2.googleapis.com/token"

	// The Google endpoint that is used to gather additional user information.
	// For more details about this endpoint, see https://developers.google.com/apis-explorer/#search/oauth2/oauth2/v2/.
	UserInformationEndpoint = "https://www.googleapis.com/oauth2/v2/userinfo"
)

const (
	AccessTypeKey           = "access_type"
	ApprovalPromptKey       = "approval_prompt"
	IncludeGrantedScopesKey = "include_granted_scopes"
	LoginHintKey            = "login_hint"
	PromptParameterKey      = "prompt"
)
