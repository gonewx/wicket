// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package facebook

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth/oauth"
	oauthcore "github.com/gonewx/wicket/auth/oauth/core"
	claimspkg "github.com/gonewx/wicket/claims"
)

type Options struct {
	*oauthcore.Options

	// Gets or sets if the appsecret_proof should be generated and sent with Facebook API calls.
	// See https://developers.facebook.com/docs/graph-api/securing-requests/#appsecret_proof for more details.
	SendAppSecretProof bool

	fields []string
}

func NewOptions() *Options {
	o := &Options{
		Options: oauthcore.NewOptions(),
	}

	o.SetCallbackPath("/signin-facebook")
	o.SendAppSecretProof = true
	o.SetAuthorizationEndpoint(AuthorizationEndpoint)
	o.SetTokenEndpoint(TokenEndpoint)
	o.SetUserInformationEndpoint(UserInformationEndpoint)
	o.AddScope("email")
	o.AddFields("name", "email", "first_name", "last_name")

	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.NameIdentifier, "id"))
	o.AddClaimAction(oauth.NewJsonSubKeyClaimAction("urn:facebook:age_range_min", "age_range", "min"))
	o.AddClaimAction(oauth.NewJsonSubKeyClaimAction("urn:facebook:age_range_max", "age_range", "max"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.DateOfBirth, "birthday"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.Email, "email"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.Name, "name"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.GivenName, "first_name"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction("urn:facebook:middle_name", "middle_name"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.Surname, "last_name"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.Gender, "gender"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction("urn:facebook:link", "link"))
	o.AddClaimAction(oauth.NewJsonSubKeyClaimAction("urn:facebook:location", "location", "name"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction(claimspkg.Locality, "locale"))
	o.AddClaimAction(oauth.NewJsonKeyClaimAction("urn:facebook:timezone", "timezone"))

	return o
}

func (*Options) New() *Options {
	return NewOptions()
}

// Validate Check that the options are valid.  Should throw an exception if things are not ok.
func (o *Options) Validate() error {
	if strings.TrimSpace(o.AppId()) == "" {
		return fmt.Errorf("Exception_OptionMustBeProvided : AppId : %w", wicket.ArgumentNullException)
	}

	if strings.TrimSpace(o.AppSecret()) == "" {
		return fmt.Errorf("Exception_OptionMustBeProvided : AppSecret : %w", wicket.ArgumentNullException)
	}

	return o.Options.Validate()
}

// Facebook uses a non-standard term for this field.
// Gets or sets the Facebook-assigned App ID.
func (o *Options) AppId() string {
	return o.ClientId()
}

func (o *Options) SetAppId(value string) {
	o.SetClientId(value)
}

// Facebook uses a non-standard term for this field.
// Gets or sets the Facebook-assigned app secret.
func (o *Options) AppSecret() string {
	return o.ClientSecret()
}

func (o *Options) SetAppSecret(value string) {
	o.SetClientSecret(value)
}

// The list of fields to retrieve from the UserInformationEndpoint.
// https://developers.facebook.com/docs/graph-api/reference/user
// Defaults to include the following fields if none are specified: "name", "email", "first_name", and "last_name".
func (o *Options) Fields() []string {
	return o.fields
}

func (o *Options) AddFields(value ...string) {
	for _, v := range value {
		if !slices.Contains(o.fields, v) {
			o.fields = append(o.fields, v)
		}
	}
}
