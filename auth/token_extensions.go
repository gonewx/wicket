// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gonewx/wicket"
)

const (
	TokenNamesKey  = ".TokenNames"
	TokenKeyPrefix = ".Token."
)

// StoreTokens Stores a set of authentication tokens, after removing any old tokens.
func StoreTokens(properties *Properties, tokens []*Token) error {
	if properties == nil {
		return gois.ArgumentNullException
	}
	if tokens == nil {
		return gois.ArgumentNullException
	}

	// Clear old tokens first
	oldTokens := properties.GetTokens()
	for _, t := range oldTokens {
		delete(properties.Items, TokenKeyPrefix+t.Name)
	}
	delete(properties.Items, TokenNamesKey)

	tokenNames := make([]string, 0)
	for _, token := range tokens {
		if token.Name == "" {
			return fmt.Errorf("Token name cannot be null: %w", gois.ArgumentNullException)
		}

		// REVIEW: should probably check that there are no ; in the token name and throw or encode
		tokenNames = append(tokenNames, token.Name)
		properties.Items[TokenKeyPrefix+token.Name] = token.Value
	}
	if len(tokenNames) > 0 {
		properties.Items[TokenNamesKey] = strings.Join(tokenNames, ";")
	}

	return nil
}

func GetTokenValue(properties *Properties, tokenName string) (string, error) {
	if properties == nil {
		return "", gois.ArgumentNullException
	}
	if tokenName == "" {
		return "", gois.ArgumentNullException
	}

	tokenKey := TokenKeyPrefix + tokenName

	if properties.Items == nil {
		return "", nil
	}

	token, ok := properties.Items[tokenKey]
	if !ok {
		return "", nil
	}

	return token, nil
}

func GetToken(request *http.Request, response http.ResponseWriter, auth Service, scheme string, tokenName string) (string, error) {
	if auth == nil {
		return "", gois.ArgumentNullException
	}

	if tokenName == "" {
		return "", gois.ArgumentNullException
	}

	result, err := auth.Authenticate(request, response, scheme)
	if err != nil {
		return "", err
	}

	if result == nil {
		return "", nil
	}

	if result.Properties == nil {
		return "", nil
	}

	return GetTokenValue(result.Properties, tokenName)
}
