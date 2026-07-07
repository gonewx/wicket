// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package messages

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// From: IdentityServer4/src/IdentityServer/ResponseHandling/Models/AuthorizeResponse.cs
type authorizeResponseTests struct {
	Raw string

	Values url.Values
}

func NewAuthorizeResponseTests(raw string) *authorizeResponseTests {
	return &authorizeResponseTests{}
}

func TestError_Response_with_QueryString(t *testing.T) {
	a := require.New(t)

	u := "http://server/callback?error=foo"

	response := NewAuthorizeResponse(u)

	a.True(response.IsError())
	a.Equal("foo", response.Error())
}

func TestError_Response_with_HashFragment(t *testing.T) {
	a := require.New(t)

	u := "http://server/callback#error=foo"

	response := NewAuthorizeResponse(u)

	a.True(response.IsError())
	a.Equal("foo", response.Error())
}

func TestError_Response_with_QueryString_and_HashFragment(t *testing.T) {
	a := require.New(t)

	u := "http://server/callback?error=foo#_=_"

	response := NewAuthorizeResponse(u)

	a.True(response.IsError())
	a.Equal("foo", response.Error())
}

func TestCode_Response_with_QueryString(t *testing.T) {
	a := require.New(t)

	u := "http://server/callback?code=foo&sid=123"

	response := NewAuthorizeResponse(u)

	a.False(response.IsError())
	a.Equal("foo", response.Code())

	a.Equal("123", response.Values.Get("sid"))
	a.Equal("123", response.TryGet("sid"))
}

func TestAccessToken_Response_with_QueryString(t *testing.T) {
	a := require.New(t)

	u := "http://server/callback#access_token=foo&sid=123"

	response := NewAuthorizeResponse(u)

	a.False(response.IsError())
	a.Equal("foo", response.AccessToken())

	a.Equal("123", response.Values.Get("sid"))
	a.Equal("123", response.TryGet("sid"))
}

func TestAccessToken_Response_with_QueryString_and_HashFragment(t *testing.T) {
	a := require.New(t)

	u := "http://server/callback?access_token=foo&sid=123#_=_"

	response := NewAuthorizeResponse(u)

	a.False(response.IsError())
	a.Equal("foo", response.AccessToken())

	a.Equal("123", response.Values.Get("sid"))
	a.Equal("123", response.TryGet("sid"))
}

func TestAccessToken_Response_with_QueryString_and_Empty_Entry(t *testing.T) {
	a := require.New(t)

	u := "http://server/callback?access_token=foo&&sid=123&"

	response := NewAuthorizeResponse(u)

	a.False(response.IsError())
	a.Equal("foo", response.AccessToken())

	a.Equal("123", response.Values.Get("sid"))
	a.Equal("123", response.TryGet("sid"))
}

func TestForm_post_format_should_parse(t *testing.T) {
	a := require.New(t)

	form := "id_token=foo&code=bar&scope=baz&session_state=quux"

	response := NewAuthorizeResponse(form)

	a.False(response.IsError())
	a.Equal("foo", response.IdentityToken())
	a.Equal("bar", response.Code())
	a.Equal("baz", response.Scope())
	a.Equal("quux", response.Values.Get("session_state"))
}
