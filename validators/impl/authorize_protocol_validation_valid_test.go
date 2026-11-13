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
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)

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
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)

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
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid resource")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)

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
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, "resource")
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesToken)

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
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesIdToken)
				values.Add(wicket.AuthorizeRequestNonce, "abc")

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
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, "openid resource")
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesIdTokenToken)
				values.Add(wicket.AuthorizeRequestNonce, "abc")

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
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, wicket.StandardScopesOpenId)
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesIdToken)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesFormPost)
				values.Add(wicket.AuthorizeRequestNonce, "abc")

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
				values.Add(wicket.AuthorizeRequestClientId, "implicitclient")
				values.Add(wicket.AuthorizeRequestScope, "openid resource")
				values.Add(wicket.AuthorizeRequestRedirectUri, "oob://implicit/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesIdTokenToken)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesFormPost)
				values.Add(wicket.AuthorizeRequestNonce, "abc")

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
				values.Add(wicket.AuthorizeRequestClientId, "hybridclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestNonce, "nonce")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCodeToken)

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
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesFragment)

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
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesFragment)
				values.Add(wicket.AuthorizeRequestPrompt, wicket.PromptModesNone)

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
				values.Add(wicket.AuthorizeRequestClientId, "codeclient")
				values.Add(wicket.AuthorizeRequestScope, "openid")
				values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)
				values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesFragment)
				values.Add(wicket.AuthorizeRequestPrompt, wicket.PromptModesConsent+" "+wicket.PromptModesLogin)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
				r.Len(result.ValidatedRequest.PromptModes, 2)
				r.Contains(result.ValidatedRequest.PromptModes, wicket.PromptModesLogin)
				r.Contains(result.ValidatedRequest.PromptModes, wicket.PromptModesConsent)
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
	values.Add(wicket.AuthorizeRequestClientId, "codeclient")
	values.Add(wicket.AuthorizeRequestScope, "openid")
	values.Add(wicket.AuthorizeRequestRedirectUri, "https://server/cb")
	values.Add(wicket.AuthorizeRequestResponseType, wicket.ResponseTypesCode)
	values.Add(wicket.AuthorizeRequestResponseMode, wicket.ResponseModesFragment)

	values.Set(wicket.AuthorizeRequestPrompt, "consent login")

	t.Run("case1", func(t *testing.T) {
		r := require.New(t)

		validator, err := createAuthorizeRequestValidator()
		r.NoError(err)

		result := validator.Validate(context.Background(), values, nil)
		r.NoError(result.Error)

		r.ElementsMatch(result.ValidatedRequest.PromptModes, []string{wicket.PromptModesConsent, wicket.PromptModesLogin})

	})

	t.Run("case2", func(t *testing.T) {
		r := require.New(t)

		values.Set(wicket.SuppressedPrompt, "login")

		validator, err := createAuthorizeRequestValidator()
		r.NoError(err)

		result := validator.Validate(context.Background(), values, nil)

		r.NoError(result.Error)
		r.ElementsMatch(result.ValidatedRequest.PromptModes, []string{wicket.PromptModesConsent})
		r.ElementsMatch(result.ValidatedRequest.OriginalPromptModes, []string{wicket.PromptModesConsent, wicket.PromptModesLogin})
		r.ElementsMatch(result.ValidatedRequest.SuppressedPromptModes, []string{wicket.PromptModesLogin})

	})

	t.Run("case3", func(t *testing.T) {
		r := require.New(t)

		values.Set(wicket.SuppressedPrompt, "login consent")

		validator, err := createAuthorizeRequestValidator()
		r.NoError(err)

		result := validator.Validate(context.Background(), values, nil)

		r.NoError(result.Error)
		r.Empty(result.ValidatedRequest.PromptModes)
		r.ElementsMatch(result.ValidatedRequest.OriginalPromptModes, []string{wicket.PromptModesConsent, wicket.PromptModesLogin})
		r.ElementsMatch(result.ValidatedRequest.SuppressedPromptModes, []string{wicket.PromptModesConsent, wicket.PromptModesLogin})

	})
}
