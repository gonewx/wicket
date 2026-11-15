// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"testing"

	"github.com/gonewx/wicket/dpop"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
)

type dpopDeclarations struct {
	dpop bool
}

func (dpopDeclarations) PrivateKeyJwtEnabled() bool { return false }

func (d dpopDeclarations) DPoPEnabled() bool { return d.dpop }

func TestClientConfigurationValidatorDPoPRule(t *testing.T) {
	t.Parallel()
	const notEnabled = "client requires DPoP but the feature is not enabled"
	const viaBrowser = "client requires DPoP but allows access tokens via the browser"
	cases := map[string]struct {
		require  bool
		browser  bool
		public   bool
		features validators.ClientFeatureDeclarations
		message  string
	}{
		"required and enabled":                {require: true, features: dpopDeclarations{dpop: true}},
		"required by a public client":         {require: true, public: true, features: dpopDeclarations{dpop: true}},
		"required and not enabled":            {require: true, features: dpopDeclarations{}, message: notEnabled},
		"required without a declaration":      {require: true, message: notEnabled},
		"required by a source without DPoP":   {require: true, features: &featureDeclarations{privateKeyJwt: true}, message: notEnabled},
		"required with browser access tokens": {require: true, browser: true, features: dpopDeclarations{dpop: true}, message: viaBrowser},
		"not required and not enabled":        {features: dpopDeclarations{}},
		"not required with browser tokens":    {browser: true, features: dpopDeclarations{dpop: true}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := storage_models.NewClient()
			client.ClientId = "client"
			client.RequireDPoP = tc.require
			client.AllowAccessTokensViaBrowser = tc.browser
			client.RequireClientSecret = !tc.public
			context := validators_contexts.NewClientConfigurationValidationContext(client)
			NewClientConfigurationValidator(tc.features).Validate(context)
			if tc.message == "" {
				if !context.IsValid {
					t.Fatalf("invalid: %q", context.ErrorMessage)
				}
				return
			}
			if context.IsValid || context.ErrorMessage != tc.message {
				t.Fatalf("valid=%v message=%q, want %q", context.IsValid, context.ErrorMessage, tc.message)
			}
		})
	}
}

func TestRefreshTokenProofBindingHolds(t *testing.T) {
	t.Parallel()
	bound := storage_models.NewRefreshToken()
	bound.DPoPKeyThumbprint = "key-a"
	unbound := storage_models.NewRefreshToken()
	background := context.Background()
	cases := map[string]struct {
		ctx   context.Context
		token *storage_models.RefreshToken
		holds bool
	}{
		"bound with the same key": {dpop.WithProof(background, "key-a"), bound, true},
		"bound with another key":  {dpop.WithProof(background, "key-b"), bound, false},
		"bound without a proof":   {background, bound, false},
		"unbound without a proof": {background, unbound, true},
		"unbound with a proof":    {dpop.WithProof(background, "key-b"), unbound, true},
		"no token is not judged":  {background, nil, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := refreshTokenProofBindingHolds(tc.ctx, tc.token); got != tc.holds {
				t.Fatalf("holds = %v, want %v", got, tc.holds)
			}
		})
	}
}
