// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
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
			responseType: gois.ResponseTypesCode,
			wantErr:      gois.AuthorizeErrorsInvalidScope,
		},
		"code client with unregistered redirect uri is invalid request": {
			clientId:     "codeclient",
			scope:        gois.StandardScopesOpenId,
			redirectUri:  "https://invalid",
			responseType: gois.ResponseTypesCode,
			wantErr:      gois.AuthorizeErrorsInvalidRequest,
		},
		"code client requesting id_token is unauthorized": {
			clientId:     "codeclient",
			scope:        gois.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: gois.ResponseTypesIdToken,
			nonce:        "abc",
			wantErr:      gois.AuthorizeErrorsUnauthorizedClient,
		},
		"code client requesting id_token token is unauthorized": {
			clientId:     "codeclient",
			scope:        gois.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: gois.ResponseTypesIdTokenToken,
			nonce:        "abc",
			wantErr:      gois.AuthorizeErrorsUnauthorizedClient,
		},
		"unknown client is unauthorized": {
			clientId:     "unknown",
			scope:        gois.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: gois.ResponseTypesCode,
			wantErr:      gois.AuthorizeErrorsUnauthorizedClient,
		},
		"restricted client requesting disallowed scope is invalid scope": {
			clientId:     "codeclient_restricted",
			scope:        "openid profile",
			redirectUri:  "https://server/cb",
			responseType: gois.ResponseTypesCode,
			wantErr:      gois.AuthorizeErrorsInvalidScope,
		},
		"id_token request mixing api scope is invalid scope": {
			clientId:     "implicitclient",
			scope:        "openid resource",
			redirectUri:  "oob://implicit/cb",
			responseType: gois.ResponseTypesIdToken,
			nonce:        "abc",
			wantErr:      gois.AuthorizeErrorsInvalidScope,
		},
		"non oidc protocol client is unauthorized": {
			clientId:     "saml2p-gap",
			scope:        gois.StandardScopesOpenId,
			redirectUri:  "http://saml2p-gap/callback",
			responseType: gois.ResponseTypesIdToken,
			nonce:        "abc",
			wantErr:      gois.AuthorizeErrorsUnauthorizedClient,
		},
		"token request with identity scope but without openid is invalid scope": {
			clientId:     "implicitclient",
			scope:        "resource profile",
			redirectUri:  "oob://implicit/cb",
			responseType: gois.ResponseTypesToken,
			wantErr:      gois.AuthorizeErrorsInvalidScope,
		},
		"implicit client without browser access tokens is invalid request": {
			clientId:     "implicitclient_no_aavb",
			scope:        gois.StandardScopesOpenId,
			redirectUri:  "oob://implicit/cb",
			responseType: gois.ResponseTypesIdTokenToken,
			nonce:        "abc",
			wantErr:      gois.AuthorizeErrorsInvalidRequest,
		},
		"hybrid client without browser access tokens is invalid request": {
			clientId:     "hybridclient_no_aavb",
			scope:        gois.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: gois.ResponseTypesCodeIdTokenToken,
			nonce:        "abc",
			wantErr:      gois.AuthorizeErrorsInvalidRequest,
		},
		"code request with multiple scopes succeeds": {
			clientId:     "codeclient",
			scope:        "openid profile resource",
			redirectUri:  "https://server/cb",
			responseType: gois.ResponseTypesCode,
		},
		"hybrid code id_token request succeeds": {
			clientId:     "hybridclient",
			scope:        gois.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: gois.ResponseTypesCodeIdToken,
			nonce:        "abc",
		},
		"hybrid code id_token token request succeeds": {
			clientId:     "hybridclient",
			scope:        gois.StandardScopesOpenId,
			redirectUri:  "https://server/cb",
			responseType: gois.ResponseTypesCodeIdTokenToken,
			nonce:        "abc",
		},
		"hybrid code id_token request with mixed scopes succeeds": {
			clientId:     "hybridclient",
			scope:        "openid resource",
			redirectUri:  "https://server/cb",
			responseType: gois.ResponseTypesCodeIdToken,
			nonce:        "abc",
		},
		"hybrid code id_token token request with mixed scopes succeeds": {
			clientId:     "hybridclient",
			scope:        "openid resource",
			redirectUri:  "https://server/cb",
			responseType: gois.ResponseTypesCodeIdTokenToken,
			nonce:        "abc",
		},
		"implicit id_token token request succeeds": {
			clientId:     "implicitclient",
			scope:        gois.StandardScopesOpenId,
			redirectUri:  "oob://implicit/cb",
			responseType: gois.ResponseTypesIdTokenToken,
			nonce:        "abc",
		},
		"implicit id_token token request with multiple scopes succeeds": {
			clientId:     "implicitclient",
			scope:        "openid profile resource",
			redirectUri:  "oob://implicit/cb",
			responseType: gois.ResponseTypesIdTokenToken,
			nonce:        "abc",
		},
		"response type value order is not significant": {
			clientId:     "implicitclient",
			scope:        gois.StandardScopesOpenId,
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
			values.Set(gois.AuthorizeRequestClientId, tt.clientId)
			values.Set(gois.AuthorizeRequestScope, tt.scope)
			values.Set(gois.AuthorizeRequestRedirectUri, tt.redirectUri)
			values.Set(gois.AuthorizeRequestResponseType, tt.responseType)
			if tt.nonce != "" {
				values.Set(gois.AuthorizeRequestNonce, tt.nonce)
			}

			result := validator.Validate(context.Background(), values, nil)
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
		})
	}
}
