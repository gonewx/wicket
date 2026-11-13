// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package facebook

import "github.com/gonewx/wicket"

const (
	// The default value used for Options.AuthenticationScheme
	AuthenticationScheme = wicket.FacebookAuthenticationScheme

	// The default display name for Facebook authentication.
	DisplayName = "Facebook"

	// The default endpoint used to perform Facebook authentication.
	// For more details about this endpoint, see https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#login
	AuthorizationEndpoint = "https://www.facebook.com/v11.0/dialog/oauth"

	// The OAuth endpoint used to retrieve access tokens.
	TokenEndpoint = "https://graph.facebook.com/v11.0/oauth/access_token"

	// The Facebook Graph API endpoint that is used to gather additional user information.
	UserInformationEndpoint = "https://graph.facebook.com/v11.0/me"
)
