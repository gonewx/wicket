// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package google

import (
	"github.com/gonewx/wicket/auth/oauth"
	oauthcore "github.com/gonewx/wicket/auth/oauth/core"
	claimspkg "github.com/gonewx/wicket/claims"
)

type Options struct {
	*oauthcore.Options

	// Indicates whether your application can refresh access tokens when the user is not present at the browser.
	// Valid values are online which is the default value, and offline.
	// Set the value to offline if your application needs to refresh access tokens when the user is not present at the browser.
	AccessType *string
}

func NewOptions() *Options {
	o := &Options{
		Options: oauthcore.NewOptions(),
	}

	o.SetCallbackPath("/signin-google")
	o.SetAuthorizationEndpoint(AuthorizationEndpoint)
	o.SetTokenEndpoint(TokenEndpoint)
	o.SetUserInformationEndpoint(UserInformationEndpoint)
	o.AddScope("openid")
	o.AddScope("profile")
	o.AddScope("email")

	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.NameIdentifier, "id"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.Name, "name"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.GivenName, "given_name"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.Surname, "family_name"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction("urn:google:profile", "link"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.Email, "email"))

	return o
}

func (*Options) New() *Options {
	return NewOptions()
}
