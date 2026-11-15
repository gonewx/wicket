// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/validators"
)

func TestAuthorizeClientRuleValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId     string
		scope        string
		redirectUri  string
		responseType string
		nonce        string
		wantErr      error
	}{
		"code client requesting unknown scope is invalid scope": {
			clientId:     "codeclient",
			scope:        "unknown",
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesCode,
			wantErr:      wicket.AuthorizeErrorsInvalidScope,
		},
		"code client with unregistered redirect uri is invalid request": {
			clientId:     "codeclient",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "https://invalid",
			responseType: wicket.ResponseTypesCode,
			wantErr:      wicket.AuthorizeErrorsInvalidRequest,
		},
		"code client requesting id_token is unauthorized": {
			clientId:     "codeclient",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesIdToken,
			nonce:        "abc",
			wantErr:      wicket.AuthorizeErrorsUnauthorizedClient,
		},
		"code client requesting id_token token is unauthorized": {
			clientId:     "codeclient",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesIdTokenToken,
			nonce:        "abc",
			wantErr:      wicket.AuthorizeErrorsUnauthorizedClient,
		},
		"unknown client is unauthorized": {
			clientId:     "unknown",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesCode,
			wantErr:      wicket.AuthorizeErrorsUnauthorizedClient,
		},
		"restricted client requesting disallowed scope is invalid scope": {
			clientId:     "codeclient_restricted",
			scope:        "openid profile",
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesCode,
			wantErr:      wicket.AuthorizeErrorsInvalidScope,
		},
		"id_token request mixing api scope is invalid scope": {
			clientId:     "implicitclient",
			scope:        "openid resource",
			redirectUri:  "oob://implicit/cb",
			responseType: wicket.ResponseTypesIdToken,
			nonce:        "abc",
			wantErr:      wicket.AuthorizeErrorsInvalidScope,
		},
		"non oidc protocol client is unauthorized": {
			clientId:     "saml2p-gap",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "http://saml2p-gap/callback",
			responseType: wicket.ResponseTypesIdToken,
			nonce:        "abc",
			wantErr:      wicket.AuthorizeErrorsUnauthorizedClient,
		},
		"token request with identity scope but without openid is invalid scope": {
			clientId:     "implicitclient",
			scope:        "resource profile",
			redirectUri:  "oob://implicit/cb",
			responseType: wicket.ResponseTypesToken,
			wantErr:      wicket.AuthorizeErrorsInvalidScope,
		},
		"implicit client without browser access tokens is invalid request": {
			clientId:     "implicitclient_no_aavb",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "oob://implicit/cb",
			responseType: wicket.ResponseTypesIdTokenToken,
			nonce:        "abc",
			wantErr:      wicket.AuthorizeErrorsInvalidRequest,
		},
		"hybrid client without browser access tokens is invalid request": {
			clientId:     "hybridclient_no_aavb",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesCodeIdTokenToken,
			nonce:        "abc",
			wantErr:      wicket.AuthorizeErrorsInvalidRequest,
		},
		"code request with multiple scopes succeeds": {
			clientId:     "codeclient",
			scope:        "openid profile resource",
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesCode,
		},
		"hybrid code id_token request succeeds": {
			clientId:     "hybridclient",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesCodeIdToken,
			nonce:        "abc",
		},
		"hybrid code id_token token request succeeds": {
			clientId:     "hybridclient",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesCodeIdTokenToken,
			nonce:        "abc",
		},
		"hybrid code id_token request with mixed scopes succeeds": {
			clientId:     "hybridclient",
			scope:        "openid resource",
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesCodeIdToken,
			nonce:        "abc",
		},
		"hybrid code id_token token request with mixed scopes succeeds": {
			clientId:     "hybridclient",
			scope:        "openid resource",
			redirectUri:  "https://server/cb",
			responseType: wicket.ResponseTypesCodeIdTokenToken,
			nonce:        "abc",
		},
		"implicit id_token token request succeeds": {
			clientId:     "implicitclient",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "oob://implicit/cb",
			responseType: wicket.ResponseTypesIdTokenToken,
			nonce:        "abc",
		},
		"implicit id_token token request with multiple scopes succeeds": {
			clientId:     "implicitclient",
			scope:        "openid profile resource",
			redirectUri:  "oob://implicit/cb",
			responseType: wicket.ResponseTypesIdTokenToken,
			nonce:        "abc",
		},
		"response type value order is not significant": {
			clientId:     "implicitclient",
			scope:        wicket.StandardScopesOpenId,
			redirectUri:  "oob://implicit/cb",
			responseType: "token id_token",
			nonce:        "abc",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			validator, err := createAuthorizeRequestValidator()
			if err != nil {
				t.Fatalf("build validator: %v", err)
			}

			values := url.Values{}
			values.Set(wicket.AuthorizeRequestClientId, tt.clientId)
			values.Set(wicket.AuthorizeRequestScope, tt.scope)
			values.Set(wicket.AuthorizeRequestRedirectUri, tt.redirectUri)
			values.Set(wicket.AuthorizeRequestResponseType, tt.responseType)
			if tt.nonce != "" {
				values.Set(wicket.AuthorizeRequestNonce, tt.nonce)
			}

			result := validator.Validate(context.Background(), values, nil, validators.AuthorizeRequestPhaseEntry)
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
		})
	}
}
