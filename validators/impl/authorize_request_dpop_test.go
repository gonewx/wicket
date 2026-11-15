// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/dpop"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

func thumbprintOf(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func dpopJktRequest(values url.Values) *validators_models.ValidatedAuthorizeRequest {
	request := validators_models.NewValidatedAuthorizeRequest()
	request.Raw = values
	return request
}

func TestValidateDPoPKeyThumbprint(t *testing.T) {
	t.Parallel()
	good := thumbprintOf("key")
	// A 43 character value whose last character carries bits beyond the
	// 32 bytes is not the canonical encoding of any thumbprint.
	nonCanonical := good[:42] + string(rune(good[42]+1))
	if good[42] == 'z' || good[42] == '9' || good[42] == '_' {
		nonCanonical = good[:42] + "B"
	}
	cases := map[string]struct {
		values url.Values
		want   string
		valid  bool
	}{
		"absent":           {url.Values{}, "", true},
		"valid":            {url.Values{wicket.AuthorizeRequestDPoPJkt: {good}}, good, true},
		"empty":            {url.Values{wicket.AuthorizeRequestDPoPJkt: {""}}, "", false},
		"padded":           {url.Values{wicket.AuthorizeRequestDPoPJkt: {good + "="}}, "", false},
		"too short":        {url.Values{wicket.AuthorizeRequestDPoPJkt: {good[:42]}}, "", false},
		"too long":         {url.Values{wicket.AuthorizeRequestDPoPJkt: {good + "A"}}, "", false},
		"standard base64":  {url.Values{wicket.AuthorizeRequestDPoPJkt: {strings.Repeat("+", 43)}}, "", false},
		"whitespace":       {url.Values{wicket.AuthorizeRequestDPoPJkt: {" " + good[1:]}}, "", false},
		"non canonical":    {url.Values{wicket.AuthorizeRequestDPoPJkt: {nonCanonical}}, "", false},
		"repeated":         {url.Values{wicket.AuthorizeRequestDPoPJkt: {good, good}}, "", false},
		"hex sha256":       {url.Values{wicket.AuthorizeRequestDPoPJkt: {strings.Repeat("a", 64)}}, "", false},
		"other characters": {url.Values{wicket.AuthorizeRequestDPoPJkt: {strings.Repeat(".", 43)}}, "", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validator := &AuthorizeRequestValidator{}
			validator.SetDPoPKeyBinding()
			request := dpopJktRequest(tc.values)
			result := validator.validateDPoPKeyThumbprint(request)
			if tc.valid {
				if result != nil {
					t.Fatalf("refused: %v %s", result.Error, result.Description)
				}
				if request.DPoPKeyThumbprint != tc.want {
					t.Fatalf("thumbprint %q, want %q", request.DPoPKeyThumbprint, tc.want)
				}
				return
			}
			if result == nil || !errors.Is(result.Error, wicket.AuthorizeErrorsInvalidRequest) || result.Description != "Invalid dpop_jkt" {
				t.Fatalf("result %+v", result)
			}
			if request.DPoPKeyThumbprint != "" {
				t.Fatalf("thumbprint %q kept", request.DPoPKeyThumbprint)
			}
		})
	}
}

func TestValidateDPoPKeyThumbprintIgnoredWithoutDPoP(t *testing.T) {
	t.Parallel()
	validator := &AuthorizeRequestValidator{}
	for _, value := range []string{thumbprintOf("key"), "not a thumbprint"} {
		request := dpopJktRequest(url.Values{wicket.AuthorizeRequestDPoPJkt: {value}})
		if result := validator.validateDPoPKeyThumbprint(request); result != nil {
			t.Fatalf("%q refused although DPoP is not enabled", value)
		}
		if request.DPoPKeyThumbprint != "" {
			t.Fatalf("%q recorded although DPoP is not enabled", value)
		}
	}
}

func TestAuthorizationCodeProofBindingHolds(t *testing.T) {
	t.Parallel()
	bound := storage_models.NewAuthorizationCode()
	bound.DPoPKeyThumbprint = thumbprintOf("key")
	unbound := storage_models.NewAuthorizationCode()
	cases := map[string]struct {
		code  *storage_models.AuthorizationCode
		ctx   context.Context
		holds bool
	}{
		"unbound without proof":  {unbound, context.Background(), true},
		"unbound with proof":     {unbound, dpop.WithProof(context.Background(), thumbprintOf("other")), true},
		"nil code":               {nil, context.Background(), true},
		"bound with same key":    {bound, dpop.WithProof(context.Background(), thumbprintOf("key")), true},
		"bound with another key": {bound, dpop.WithProof(context.Background(), thumbprintOf("other")), false},
		"bound without proof":    {bound, context.Background(), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := authorizationCodeProofBindingHolds(tc.ctx, tc.code); got != tc.holds {
				t.Fatalf("holds %v, want %v", got, tc.holds)
			}
		})
	}
}
