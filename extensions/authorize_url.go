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
	setQuery(q, gois.AuthorizeRequestClientId, clientId)
	setQuery(q, gois.AuthorizeRequestResponseType, responseType)
	setQuery(q, gois.AuthorizeRequestScope, scope)
	setQuery(q, gois.AuthorizeRequestRedirectUri, redirectUri)
	setQuery(q, gois.AuthorizeRequestState, state)
	setQuery(q, gois.AuthorizeRequestNonce, nonce)
	setQuery(q, gois.AuthorizeRequestLoginHint, loginHint)
	setQuery(q, gois.AuthorizeRequestAcrValues, acrValues)
	setQuery(q, gois.AuthorizeRequestPrompt, prompt)
	setQuery(q, gois.AuthorizeRequestResponseMode, responseMode)
	setQuery(q, gois.AuthorizeRequestCodeChallenge, codeChallenge)
	setQuery(q, gois.AuthorizeRequestCodeChallengeMethod, codeChallengeMethod)
	setQuery(q, gois.AuthorizeRequestRequest, request)
	if maxAge > 0 {
		q.Set(gois.AuthorizeRequestMaxAge, strconv.Itoa(maxAge))
	}
	setQuery(q, gois.AuthorizeRequestDisplay, display)
	setQuery(q, gois.AuthorizeRequestUiLocales, uiLocales)
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
