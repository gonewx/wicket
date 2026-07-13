// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"fmt"
	"slices"
	"strings"

	gois "github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	authcore "github.com/gonewx/wicket/auth/core"
	"github.com/gonewx/wicket/auth/oauth"
)

var _ auth.RemoteOptions[*Options] = (*Options)(nil)

type Options struct {
	*authcore.RemoteOptions

	// Gets or sets the provider-assigned client id.
	clientId string

	// Gets or sets the provider-assigned client secret.
	clientSecret string

	// Gets or sets the URI where the client will be redirected to authenticate.
	authorizationEndpoint string

	// Gets or sets the URI the middleware will access to exchange the OAuth token.
	tokenEndpoint string

	// Gets or sets the URI the middleware will access to obtain the user information.
	// This value is not used in the default implementation, it is for use in custom implementations of Events.OnCreatingTicket
	userInformationEndpoint string

	// ClaimActions A collection of claim actions used to select values from the json user data and create Claims.
	claimActions []oauth.ClaimAction

	// Scope Gets the list of permissions to request.
	scope []string

	// StateDataFormat Gets or sets the type used to secure data handled by the middleware.
	stateDataFormat authcore.SecureDataFormat[auth.Properties]

	//UsePkce Enables or disables the use of the Proof Key for Code Exchange (PKCE) standard. See https://tools.ietf.org/html/rfc7636.
	// The default value is `false` but derived handlers should enable this if their provider supports it.
	usePkce bool
}

func NewOptions() *Options {
	o := &Options{
		RemoteOptions: authcore.NewRemoteOptions(),
		claimActions:  make([]oauth.ClaimAction, 0),
		scope:         make([]string, 0),
	}

	return o
}

func (*Options) New() *Options {
	return NewOptions()
}

func (o *Options) Events() any {
	return o.RemoteOptions.Events()
}

func (o *Options) SetEvents(value any) {
	o.RemoteOptions.SetEvents(value)
}

// Validate Check that the options are valid. Should throw an exception if things are not ok.
func (o *Options) Validate() error {
	if err := o.RemoteOptions.Validate(); err != nil {
		return err
	}

	if strings.TrimSpace(o.clientId) == "" {
		return fmt.Errorf("Exception_OptionMustBeProvided (clientId): %w", gois.ArgumentNullException)
	}

	if strings.TrimSpace(o.clientSecret) == "" {
		return fmt.Errorf("Exception_OptionMustBeProvided (clientSecret): %w", gois.ArgumentNullException)
	}

	if strings.TrimSpace(o.authorizationEndpoint) == "" {
		return fmt.Errorf("Exception_OptionMustBeProvided (authorizationEndpoint): %w", gois.ArgumentNullException)
	}

	if strings.TrimSpace(o.tokenEndpoint) == "" {
		return fmt.Errorf("Exception_OptionMustBeProvided (tokenEndpoint): %w", gois.ArgumentNullException)
	}

	if strings.TrimSpace(o.CallbackPath()) == "" {
		return fmt.Errorf("Exception_OptionMustBeProvided (CallbackPath): %w", gois.ArgumentNullException)
	}

	return nil
}

func (o *Options) ClientId() string {
	return o.clientId
}
func (o *Options) SetClientId(id string) {
	o.clientId = id
}

// Gets or sets the provider-assigned client secret.
func (o *Options) ClientSecret() string {
	return o.clientSecret
}
func (o *Options) SetClientSecret(cs string) {
	o.clientSecret = cs
}

// Gets or sets the URI where the client will be redirected to authenticate.
func (o *Options) AuthorizationEndpoint() string {
	return o.authorizationEndpoint
}
func (o *Options) SetAuthorizationEndpoint(ae string) {
	o.authorizationEndpoint = ae
}

// Gets or sets the URI the middleware will access to exchange the OAuth token.
func (o *Options) TokenEndpoint() string {
	return o.tokenEndpoint
}
func (o *Options) SetTokenEndpoint(te string) {
	o.tokenEndpoint = te
}

// Gets or sets the URI the middleware will access to obtain the user information.
// This value is not used in the default implementation, it is for use in custom implementations of Events.OnCreatingTicket
func (o *Options) UserInformationEndpoint() string {
	return o.userInformationEndpoint
}
func (o *Options) SetUserInformationEndpoint(uie string) {
	o.userInformationEndpoint = uie
}

// ClaimActions A collection of claim actions used to select values from the json user data and create Claims.
func (o *Options) ClaimActions() []oauth.ClaimAction {
	return o.claimActions
}
func (o *Options) SetClaimActions(cas []oauth.ClaimAction) {
	o.claimActions = cas
}

// gois: support claim action operation
func (o *Options) AddClaimAction(ca oauth.ClaimAction) {
	o.claimActions = append(o.claimActions, ca)
}

func (o *Options) ClearClaimActions() {
}

func (o *Options) RemoveClaimAction(claimType string) {
	o.claimActions = slices.DeleteFunc(o.claimActions, func(ca oauth.ClaimAction) bool {
		return ca.Typ() == claimType
	})
}

// Scope Gets the list of permissions to request.
func (o *Options) Scope() []string {
	return o.scope
}
func (o *Options) SetScope(s []string) {
	o.scope = s
}

// gois: support scope operation
func (o *Options) AddScope(s string) {
	if !slices.Contains(o.scope, s) {
		o.scope = append(o.scope, s)
	}
}

func (o *Options) ClearScope() {
	o.scope = make([]string, 0)
}

// StateDataFormat Gets or sets the type used to secure data handled by the middleware.
func (o *Options) StateDataFormat() authcore.SecureDataFormat[auth.Properties] {
	return o.stateDataFormat
}
func (o *Options) SetStateDataFormat(sdf authcore.SecureDataFormat[auth.Properties]) {
	o.stateDataFormat = sdf
}

// UsePkce Enables or disables the use of the Proof Key for Code Exchange (PKCE) standard. See https://tools.ietf.org/html/rfc7636.
// The default value is `false` but derived handlers should enable this if their provider supports it.
func (o *Options) UsePkce() bool {
	return o.usePkce
}
func (o *Options) SetUsePkce(up bool) {
	o.usePkce = up
}
