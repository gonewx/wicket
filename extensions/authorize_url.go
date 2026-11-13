// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package extensions

import (
	"net/url"
	"strconv"

	"github.com/gonewx/wicket"
)

// CreateAuthorizeUrl builds an authorize endpoint URL.
// input: base URL and authorize parameters -> behavior: append non-empty query values -> output: URL.
func CreateAuthorizeUrl(baseURL *url.URL, clientId, responseType, scope, redirectUri, state, nonce, loginHint, acrValues, prompt, responseMode, codeChallenge, codeChallengeMethod, request string, maxAge int, display, uiLocales string, extra url.Values) *url.URL {
	if baseURL == nil {
		baseURL = &url.URL{}
	}
	out := *baseURL
	q := out.Query()
	setQuery(q, wicket.AuthorizeRequestClientId, clientId)
	setQuery(q, wicket.AuthorizeRequestResponseType, responseType)
	setQuery(q, wicket.AuthorizeRequestScope, scope)
	setQuery(q, wicket.AuthorizeRequestRedirectUri, redirectUri)
	setQuery(q, wicket.AuthorizeRequestState, state)
	setQuery(q, wicket.AuthorizeRequestNonce, nonce)
	setQuery(q, wicket.AuthorizeRequestLoginHint, loginHint)
	setQuery(q, wicket.AuthorizeRequestAcrValues, acrValues)
	setQuery(q, wicket.AuthorizeRequestPrompt, prompt)
	setQuery(q, wicket.AuthorizeRequestResponseMode, responseMode)
	setQuery(q, wicket.AuthorizeRequestCodeChallenge, codeChallenge)
	setQuery(q, wicket.AuthorizeRequestCodeChallengeMethod, codeChallengeMethod)
	setQuery(q, wicket.AuthorizeRequestRequest, request)
	if maxAge > 0 {
		q.Set(wicket.AuthorizeRequestMaxAge, strconv.Itoa(maxAge))
	}
	setQuery(q, wicket.AuthorizeRequestDisplay, display)
	setQuery(q, wicket.AuthorizeRequestUiLocales, uiLocales)
	for key, values := range extra {
		for _, value := range values {
			q.Add(key, value)
		}
	}
	out.RawQuery = q.Encode()
	return &out
}

func setQuery(values url.Values, key string, value string) {
	if value != "" {
		values.Set(key, value)
	}
}
