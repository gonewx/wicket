// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
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
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "OpenId_Token_Only_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, gois.StandardScopesOpenId)
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesToken)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidScope)
			},
		},
		{
			desc: "Resource_Only_IdToken_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, "resource")
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesIdToken)
				values.Add(gois.AuthorizeRequestNonce, "abc")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Mixed_Token_Only_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, "openid resource")
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesToken)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidScope)
			},
		},
		{
			desc: "OpenId_IdToken_Request_Nonce_Missing",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesIdToken)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Missing_ClientId",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/callback")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Missing_Scope",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Missing_RedirectUri",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "client")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Malformed_RedirectUri_malformed",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "client")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "malformed")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Malformed_RedirectUri_/malformed",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "client")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "/malformed")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Malformed_RedirectUri_Triple_Slash",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "client")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https:///attacker.com")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Missing_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsUnsupportedResponseType)
			},
		},
		{
			desc: "Unknown_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, "unknown")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsUnsupportedResponseType)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_IdToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesIdToken)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_IdTokenToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesIdTokenToken)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_CodeToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "hybridclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCodeToken)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_CodeIdToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "hybridclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCodeIdToken)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_CodeIdTokenToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "hybridclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCodeIdTokenToken)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Malformed_MaxAge",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)
				values.Add(gois.AuthorizeRequestMaxAge, "malformed")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Negative_MaxAge",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)
				values.Add(gois.AuthorizeRequestMaxAge, "-1")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_TokenIdToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, "token id_token") // Unconventional order
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "Invalid_ResponseMode_For_IdTokenCodeToken_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "hybridclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, "id_token code token") // Unconventional order
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesQuery)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
		{
			desc: "prompt_none_and_other_values_should_fail",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesFragment)
				values.Add(gois.AuthorizeRequestPrompt, "none login")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(result.Error, gois.AuthorizeErrorsInvalidRequest)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			r := require.New(t)

			validator, err := createAuthorizeRequestValidator()
			r.NoError(err)

			resp := validator.Validate(tc.parameters(), nil)
			tc.expected(r, resp)

		})
	}
}
