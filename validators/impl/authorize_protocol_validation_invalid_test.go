// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

func TestAuthorizeProtocolValidationInvalid(t *testing.T) {
	tests := []struct {
		desc       string
		parameters func() url.Values
		expected   func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult)
	}{
		{
			desc: "Empty_Parameters",
			parameters: func() url.Values {
				return nil
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "OpenId_Token_Only_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, wicket.StandardScopesOpenId)
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesToken)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidScope)
			},
		},
		{
			desc: "Resource_Only_IdToken_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, "resource")
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesIdToken)
				values.Add(wicket.AuthorizeRequestNonce, "abc")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Mixed_Token_Only_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, "openid resource")
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesToken)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidScope)
			},
		},
		{
			desc: "OpenId_IdToken_Request_Nonce_Missing",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesIdToken)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Missing_ClientId",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/callback")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Missing_Scope",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Missing_RedirectUri",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "client")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Malformed_RedirectUri_malformed",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "client")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "malformed")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Malformed_RedirectUri_/malformed",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "client")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "/malformed")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Malformed_RedirectUri_Triple_Slash",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "client")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https:///attacker.com")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Missing_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsUnsupportedResponseType)
			},
		},
		{
			desc: "Unknown_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, "unknown")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsUnsupportedResponseType)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_IdToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesIdToken)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_IdTokenToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesIdTokenToken)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_CodeToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "hybridclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCodeToken)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_CodeIdToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "hybridclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCodeIdToken)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_CodeIdTokenToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "hybridclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCodeIdTokenToken)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Malformed_MaxAge",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)
				values.Add(wicket.AuthorizeRequestMaxAge, "malformed")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Negative_MaxAge",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)
				values.Add(wicket.AuthorizeRequestMaxAge, "-1")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_TokenIdToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, "token id_token") // Unconventional order
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_IdTokenCodeToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "hybridclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, "id_token code token") // Unconventional order
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "prompt_none_and_other_values_should_fail",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesFragment)
				values.Add(wicket.AuthorizeRequestPrompt, "none login")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, wicket.AuthorizeErrorsInvalidRequest)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			r := require.New(t)

			validator, err := createAuthorizeRequestValidator()
			r.NoError(err)

			resp := validator.Validate(context.Background(), tc.parameters(), nil, validators.AuthorizeRequestPhaseEntry)
			tc.expected(r, resp)

		})
	}
}
