// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package messages

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/gonewx/wicket/client"
)

// From: IdentityServer4/src/IdentityServer/ResponseHandling/Models/AuthorizeResponse.cs
type AuthorizeResponse struct {
	Raw string

	Values url.Values
}

func NewAuthorizeResponse(raw string) *AuthorizeResponse {
	r := &AuthorizeResponse{
		Raw: raw,
	}

	_ = r.parseRaw()

	return r
}

func (r *AuthorizeResponse) parseRaw() error {
	var u *url.URL
	var err error
	if !strings.Contains(r.Raw, "?") && !strings.Contains(r.Raw, "#") {
		u = &url.URL{}

		u.RawQuery = r.Raw
	} else {
		u, err = url.Parse(r.Raw)

		if err != nil {
			return err
		}

	}

	r.Values = u.Query()

	f, err := url.ParseQuery(u.Fragment)
	if err != nil {
		return err
	}

	for k, v := range f {
		for _, vv := range v {
			r.Values.Add(k, vv)
		}
	}

	return nil
}

// Code Gets the authorization code.
func (r *AuthorizeResponse) Code() string {
	return r.TryGet(client.AuthorizeResponseCode)
}

// AccessToken Gets the access token.
func (r *AuthorizeResponse) AccessToken() string {
	return r.TryGet(client.AuthorizeResponseAccessToken)
}

// IdentityToken Gets the identity token.
func (r *AuthorizeResponse) IdentityToken() string {
	return r.TryGet(client.AuthorizeResponseIdentityToken)
}

func (r *AuthorizeResponse) Error() string {
	return r.TryGet(client.AuthorizeResponseError)
}

func (r *AuthorizeResponse) Scope() string {
	return r.TryGet(client.AuthorizeResponseScope)
}

func (r *AuthorizeResponse) TokenType() string {
	return r.TryGet(client.AuthorizeResponseTokenType)
}

func (r *AuthorizeResponse) State() string {
	return r.TryGet(client.AuthorizeResponseState)
}

func (r *AuthorizeResponse) SessionState() string {
	return r.TryGet(client.AuthorizeResponseSessionState)
}

func (r *AuthorizeResponse) Issuer() string {
	return r.TryGet(client.AuthorizeResponseIssuer)
}

func (r *AuthorizeResponse) ErrorDescription() string {
	return r.TryGet(client.AuthorizeResponseErrorDescription)
}

func (r *AuthorizeResponse) IsError() bool {
	return strings.TrimSpace(r.Error()) != ""
}

func (r *AuthorizeResponse) ExpiresIn() int {
	value := r.TryGet(client.AuthorizeResponseExpiresIn)

	theValue, _ := strconv.Atoi(value)
	return theValue
}

func (r *AuthorizeResponse) TryGet(t string) string {
	value := r.Values.Get(t)
	if value == "" {
		return ""
	}

	return value
}
