// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	test_common "github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
)

func TestNo_Header_no_Body_Get(t *testing.T) {
	r := require.New(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	validator := NewBearerTokenUsageValidator(test_common.NewTestLogger())
	result, err := validator.Validate(req)
	r.NoError(err)

	r.False(result.TokenFound)
}

func TestNo_Header_no_Body_Post(t *testing.T) {
	r := require.New(t)

	req := httptest.NewRequest(http.MethodPost, "/", nil)

	validator := NewBearerTokenUsageValidator(test_common.NewTestLogger())
	result, err := validator.Validate(req)
	r.NoError(err)

	r.False(result.TokenFound)
}

func TestNon_Bearer_Scheme_Header(t *testing.T) {
	r := require.New(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Foo Bar")

	validator := NewBearerTokenUsageValidator(test_common.NewTestLogger())
	result, err := validator.Validate(req)
	r.NoError(err)

	r.False(result.TokenFound)
}

func TestEmpty_Bearer_Scheme_Header(t *testing.T) {
	r := require.New(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer")

	validator := NewBearerTokenUsageValidator(test_common.NewTestLogger())
	result, err := validator.Validate(req)
	r.NoError(err)

	r.False(result.TokenFound)
}

func TestWhitespaces_Bearer_Scheme_Header(t *testing.T) {
	r := require.New(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer           ")

	validator := NewBearerTokenUsageValidator(test_common.NewTestLogger())
	result, err := validator.Validate(req)
	r.NoError(err)

	r.False(result.TokenFound)
}

func TestValid_Bearer_Scheme_Header(t *testing.T) {
	r := require.New(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token")

	validator := NewBearerTokenUsageValidator(test_common.NewTestLogger())
	result, err := validator.Validate(req)
	r.NoError(err)

	r.True(result.TokenFound)
	r.Equal("token", result.Token)
	r.Equal(validators_models.AuthorizationHeader, result.UsageType)
}

func TestValid_Body_Post(t *testing.T) {
	r := require.New(t)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("access_token=token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	validator := NewBearerTokenUsageValidator(test_common.NewTestLogger())
	result, err := validator.Validate(req)
	r.NoError(err)

	r.True(result.TokenFound)
	r.Equal("token", result.Token)
	r.Equal(validators_models.PostBody, result.UsageType)
}

func TestBody_Post_empty_Token(t *testing.T) {
	r := require.New(t)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("access_token="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	validator := NewBearerTokenUsageValidator(test_common.NewTestLogger())
	result, err := validator.Validate(req)
	r.NoError(err)

	r.False(result.TokenFound)
}

func TestBody_Post_Whitespace_Token(t *testing.T) {
	r := require.New(t)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("access_token=               "))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	validator := NewBearerTokenUsageValidator(test_common.NewTestLogger())
	result, err := validator.Validate(req)
	r.NoError(err)

	r.False(result.TokenFound)
}

func TestBody_Post_no_Token(t *testing.T) {
	r := require.New(t)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("foo=bar"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	validator := NewBearerTokenUsageValidator(test_common.NewTestLogger())
	result, err := validator.Validate(req)
	r.NoError(err)

	r.False(result.TokenFound)
}
