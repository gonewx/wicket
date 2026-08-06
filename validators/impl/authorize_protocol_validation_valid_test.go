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
	validators_models "github.com/gonewx/wicket/validators/models"
)

func TestAuthorizeProtocolValidationValid(t *testing.T) {
	tests := []struct {
		desc       string
		parameters func() url.Values
		expected   func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult)
	}{
		{
			desc: "Valid_OpenId_Code_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc: "Valid_Resource_Code_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc: "Valid_Mixed_Code_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid resource")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc: "Valid_Resource_Token_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, "resource")
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesToken)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc: "Valid_OpenId_IdToken_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesIdToken)
				values.Add(gois.AuthorizeRequestNonce, "abc")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc: "Valid_Mixed_IdTokenToken_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, "openid resource")
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesIdTokenToken)
				values.Add(gois.AuthorizeRequestNonce, "abc")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc: "Valid_OpenId_IdToken_With_FormPost_ResponseMode_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, gois.StandardScopesOpenId)
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesIdToken)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesFormPost)
				values.Add(gois.AuthorizeRequestNonce, "abc")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc: "Valid_OpenId_IdToken_Token_With_FormPost_ResponseMode_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "implicitclient")
				values.Add(gois.AuthorizeRequestScope, "openid resource")
				values.Add(gois.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesIdTokenToken)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesFormPost)
				values.Add(gois.AuthorizeRequestNonce, "abc")

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc: "Valid_OpenId_Code_Token_Request",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "hybridclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestNonce, "nonce")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCodeToken)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc: "Valid_ResponseMode_For_Code_ResponseType",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesFragment)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc: "anonymous_user_should_produce_session_state_value",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesFragment)
				values.Add(gois.AuthorizeRequestPrompt, gois.PromptModesNone)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
				r.NotNil(result.ValidatedRequest.SessionId)
			},
		},
		{
			desc: "multiple_prompt_values_should_be_accepted",
			parameters: func() url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, "codeclient")
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)
				values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesFragment)
				values.Add(gois.AuthorizeRequestPrompt, gois.PromptModesConsent+" "+gois.PromptModesLogin)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
				r.Len(result.ValidatedRequest.PromptModes, 2)
				r.Contains(result.ValidatedRequest.PromptModes, gois.PromptModesLogin)
				r.Contains(result.ValidatedRequest.PromptModes, gois.PromptModesConsent)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			r := require.New(t)

			validator, err := createAuthorizeRequestValidator()
			r.NoError(err)

			result := validator.Validate(context.Background(), tc.parameters(), nil)
			tc.expected(r, result)

		})
	}
}

func TestAuthorizeProtocolValidationValidSuppressedPromt(t *testing.T) {
	values := url.Values{}
	values.Add(gois.AuthorizeRequestClientId, "codeclient")
	values.Add(gois.AuthorizeRequestScope, "openid")
	values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
	values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)
	values.Add(gois.AuthorizeRequestResponseMode, gois.ResponseModesFragment)

	values.Set(gois.AuthorizeRequestPrompt, "consent login")

	t.Run("case1", func(t *testing.T) {
		r := require.New(t)

		validator, err := createAuthorizeRequestValidator()
		r.NoError(err)

		result := validator.Validate(context.Background(), values, nil)
		r.NoError(result.Error)

		r.ElementsMatch(result.ValidatedRequest.PromptModes, []string{gois.PromptModesConsent, gois.PromptModesLogin})

	})

	t.Run("case2", func(t *testing.T) {
		r := require.New(t)

		values.Set(gois.SuppressedPrompt, "login")

		validator, err := createAuthorizeRequestValidator()
		r.NoError(err)

		result := validator.Validate(context.Background(), values, nil)

		r.NoError(result.Error)
		r.ElementsMatch(result.ValidatedRequest.PromptModes, []string{gois.PromptModesConsent})
		r.ElementsMatch(result.ValidatedRequest.OriginalPromptModes, []string{gois.PromptModesConsent, gois.PromptModesLogin})
		r.ElementsMatch(result.ValidatedRequest.SuppressedPromptModes, []string{gois.PromptModesLogin})

	})

	t.Run("case3", func(t *testing.T) {
		r := require.New(t)

		values.Set(gois.SuppressedPrompt, "login consent")

		validator, err := createAuthorizeRequestValidator()
		r.NoError(err)

		result := validator.Validate(context.Background(), values, nil)

		r.NoError(result.Error)
		r.Empty(result.ValidatedRequest.PromptModes)
		r.ElementsMatch(result.ValidatedRequest.OriginalPromptModes, []string{gois.PromptModesConsent, gois.PromptModesLogin})
		r.ElementsMatch(result.ValidatedRequest.SuppressedPromptModes, []string{gois.PromptModesConsent, gois.PromptModesLogin})

	})
}
