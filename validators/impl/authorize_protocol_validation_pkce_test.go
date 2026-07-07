// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	validators_models "github.com/gonewx/wicket/validators/models"
)

func TestAuthorizeProtocolValidationPkce(t *testing.T) {
	lengths := config_options.NewInputLengthRestrictions()

	tests := []struct {
		desc       string
		clientIds  []string
		parameters func(clientid string) url.Values
		expected   func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult)
	}{
		// Authorize_ProtocolValidation_PKCE.cs
		{
			desc:      "valid_openid_code_request_with_challenge_and_plain_method_should_be_forbidden_if_plain_is_forbidden",
			clientIds: []string{"codeclient.pkce", "codeclient"},
			parameters: func(clientid string) url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, clientid)
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestCodeChallenge, strings.Repeat("x", lengths.CodeChallengeMinLength))
				values.Add(gois.AuthorizeRequestCodeChallengeMethod, gois.CodeChallengeMethodsPlain)
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.Equal("Transform algorithm not supported", result.Description)
			},
		},
		{
			desc:      "valid_openid_code_request_with_challenge_and_sh256_method_should_be_allowed",
			clientIds: []string{"codeclient.pkce", "codeclient"},
			parameters: func(clientid string) url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, clientid)
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestCodeChallenge, strings.Repeat("x", lengths.CodeChallengeMinLength))
				values.Add(gois.AuthorizeRequestCodeChallengeMethod, gois.CodeChallengeMethodsSha256)
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc:      "valid_openid_code_request_with_challenge_and_missing_method_should_be_allowed_if_plain_is_allowed",
			clientIds: []string{"codeclient.pkce.plain", "codeclient.plain"},
			parameters: func(clientid string) url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, clientid)
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestCodeChallenge, strings.Repeat("x", lengths.CodeChallengeMinLength))
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.NoError(result.Error)
			},
		},
		{
			desc:      "valid_openid_code_request_with_challenge_and_missing_method_should_be_forbidden_if_plain_is_forbidden",
			clientIds: []string{"codeclient.pkce", "codeclient"},
			parameters: func(clientid string) url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, clientid)
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestCodeChallenge, strings.Repeat("x", lengths.CodeChallengeMinLength))
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.Equal("Transform algorithm not supported", result.Description)
			},
		},
		{
			desc:      "openid_code_request_missing_challenge_should_be_rejected",
			clientIds: []string{"codeclient.pkce"},
			parameters: func(clientid string) url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, clientid)
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(gois.AuthorizeErrorsInvalidRequest, result.Error)
				r.Equal("code challenge required", result.Description)
			},
		},
		{
			desc:      "openid_hybrid_request_missing_challenge_should_be_rejected",
			clientIds: []string{"hybridclient.pkce"},
			parameters: func(clientid string) url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, clientid)
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(gois.AuthorizeErrorsInvalidRequest, result.Error)
				r.Equal("code challenge required", result.Description)
			},
		},
		{
			desc:      "openid_code_request_with_challenge_and_invalid_method_should_be_rejected",
			clientIds: []string{"codeclient.pkce", "codeclient.pkce.plain", "codeclient", "codeclient.plain"},
			parameters: func(clientid string) url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, clientid)
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestCodeChallenge, strings.Repeat("x", lengths.CodeChallengeMinLength))
				values.Add(gois.AuthorizeRequestCodeChallengeMethod, "invalid")
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(gois.AuthorizeErrorsInvalidRequest, result.Error)
				r.Equal("Transform algorithm not supported", result.Description)
			},
		},
		{
			desc:      "openid_code_request_with_too_short_challenge_should_be_rejected",
			clientIds: []string{"codeclient.pkce", "codeclient.pkce.plain", "codeclient", "codeclient.plain"},
			parameters: func(clientid string) url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, clientid)
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestCodeChallenge, strings.Repeat("x", lengths.CodeChallengeMinLength-1))
				values.Add(gois.AuthorizeRequestCodeChallengeMethod, gois.CodeChallengeMethodsPlain)
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(gois.AuthorizeErrorsInvalidRequest, result.Error)
			},
		},
		{
			desc:      "openid_code_request_with_too_long_challenge_should_be_rejected",
			clientIds: []string{"codeclient.pkce", "codeclient.pkce.plain", "codeclient", "codeclient.plain"},
			parameters: func(clientid string) url.Values {
				values := url.Values{}
				values.Add(gois.AuthorizeRequestClientId, clientid)
				values.Add(gois.AuthorizeRequestScope, "openid")
				values.Add(gois.AuthorizeRequestCodeChallenge, strings.Repeat("x", lengths.CodeChallengeMaxLength+1))
				values.Add(gois.AuthorizeRequestCodeChallengeMethod, gois.CodeChallengeMethodsPlain)
				values.Add(gois.AuthorizeRequestRedirectUri, "https://server/cb")
				values.Add(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

				return values
			},
			expected: func(r *require.Assertions, result *validators_models.AuthorizeRequestValidationResult) {
				r.Error(result.Error)
				r.ErrorIs(gois.AuthorizeErrorsInvalidRequest, result.Error)
			},
		},
	}

	for _, tc := range tests {
		for _, clientId := range tc.clientIds {
			t.Run(tc.desc+clientId, func(t *testing.T) {
				r := require.New(t)
				validator, err := createAuthorizeRequestValidator()
				r.NoError(err)

				resp := validator.Validate(tc.parameters(clientId), nil)
				tc.expected(r, resp)
			})
		}
	}
}
