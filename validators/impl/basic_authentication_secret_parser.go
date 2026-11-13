// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"encoding/base64"
	"html"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gonewx/wicket"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
)

// BasicAuthenticationSecretParser Parses a Basic Authentication header
type BasicAuthenticationSecretParser struct {
	logger  *slog.Logger
	options *config_options.WicketOptions
}

func NewBasicAuthenticationSecretParser(
	logger *slog.Logger,
	options *config_options.WicketOptions,
) *BasicAuthenticationSecretParser {
	return &BasicAuthenticationSecretParser{
		logger:  logger,
		options: options,
	}
}

// Tries to find the best secret on the context that can be used for authentication
func (p *BasicAuthenticationSecretParser) Parse(request *http.Request) (*models.ParsedSecret, error) {
	p.logger.Debug("Start parsing Basic Authentication secret")

	authorizationHeader := request.Header.Get("Authorization")
	if authorizationHeader == "" {
		return nil, nil
	}

	if !strings.HasPrefix(authorizationHeader, "Basic ") {
		return nil, nil
	}

	parameter := strings.TrimPrefix(authorizationHeader, "Basic ")

	pair, err := base64.StdEncoding.DecodeString(parameter)
	if err != nil {
		p.logger.Warn("Malformed Basic Authentication credential.")
		return nil, err
	}

	clientId, secret, found := strings.Cut(string(pair), ":")
	if !found {
		p.logger.Warn("Malformed Basic Authentication credential.")
		return nil, err
	}

	if clientId == "" {
		p.logger.Debug("No Basic Authentication secret found")
		return nil, nil
	}

	if len(clientId) > p.options.InputLengthRestrictions.ClientId {
		p.logger.Error("Client ID exceeds maximum length.")
		return nil, nil
	}

	if secret != "" {
		if len(secret) > p.options.InputLengthRestrictions.ClientSecret {
			p.logger.Error("Client secret exceeds maximum length.")
			return nil, nil
		}

		parsedSecret := &models.ParsedSecret{
			Id:         p.Decode(clientId),
			Credential: p.Decode(secret),
			Type:       wicket.ParsedSecretTypesSharedSecret,
		}

		return parsedSecret, nil
	} else {
		// client secret is optional
		p.logger.Debug("client id without secret found")

		parsedSecret := &models.ParsedSecret{
			Id:   p.Decode(clientId),
			Type: wicket.ParsedSecretTypesNoSecret,
		}

		return parsedSecret, nil
	}
}

// Returns the authentication method name that this parser implements
func (p *BasicAuthenticationSecretParser) AuthenticationMethod() string {
	return wicket.EndpointAuthenticationMethodsBasicAuthentication
}

// RFC6749 says individual values must be application/x-www-form-urlencoded
// 2.3.1
func (p *BasicAuthenticationSecretParser) Decode(value string) string {
	if value == "" {
		return ""
	}

	return html.UnescapeString(strings.Replace(value, "+", "%20", -1))
}
