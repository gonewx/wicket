// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package oauth

import (
	"github.com/gonewx/wicket/auth"
	authcore "github.com/gonewx/wicket/auth/core"
)

type Options[T any] interface {
	auth.RemoteOptions[T]

	// Gets or sets the provider-assigned client id.
	ClientId() string
	SetClientId(string)

	// Gets or sets the provider-assigned client secret.
	ClientSecret() string
	SetClientSecret(string)

	// Gets or sets the URI where the client will be redirected to authenticate.
	AuthorizationEndpoint() string
	SetAuthorizationEndpoint(string)

	// Gets or sets the URI the middleware will access to exchange the OAuth token.
	TokenEndpoint() string
	SetTokenEndpoint(string)

	// Gets or sets the URI the middleware will access to obtain the user information.
	// This value is not used in the default implementation, it is for use in custom implementations of Events.OnCreatingTicket
	UserInformationEndpoint() string
	SetUserInformationEndpoint(string)

	// ClaimActions A collection of claim actions used to select values from the json user data and create Claims.
	ClaimActions() []ClaimAction
	SetClaimActions([]ClaimAction)

	// Scope Gets the list of permissions to request.
	Scope() []string
	SetScope([]string)

	// StateDataFormat Gets or sets the type used to secure data handled by the middleware.
	StateDataFormat() authcore.SecureDataFormat[auth.Properties]
	SetStateDataFormat(authcore.SecureDataFormat[auth.Properties])

	//UsePkce Enables or disables the use of the Proof Key for Code Exchange (PKCE) standard. See https://tools.ietf.org/html/rfc7636.
	// The default value is `false` but derived handlers should enable this if their provider supports it.
	UsePkce() bool
	SetUsePkce(bool)
}
