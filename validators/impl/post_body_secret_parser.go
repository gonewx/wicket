// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"log/slog"
	"mime"
	"net/http"

	"github.com/gonewx/wicket"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
)

// PostBodySecretParser Parses a POST body for secrets
type PostBodySecretParser struct {
	logger  *slog.Logger
	options *config_options.IdentityServerOptions
}

func NewPostBodySecretParser(
	logger *slog.Logger,
	options *config_options.IdentityServerOptions,
) *PostBodySecretParser {
	return &PostBodySecretParser{
		logger:  logger,
		options: options,
	}
}

// Parse Tries to find a secret on the context that can be used for authentication
func (p *PostBodySecretParser) Parse(request *http.Request) (*models.ParsedSecret, error) {
	p.logger.Debug("Start parsing for secret in post body")

	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		p.logger.Error("Content type is not a form")
		return nil, nil
	}

	if err := request.ParseForm(); err != nil {
		p.logger.Error("No secret in post body found")
		return nil, nil
	}

	body := request.PostForm

	id := body.Get("client_id")
	secret := body.Get("client_secret")

	// client id must be present
	if id == "" {
		p.logger.Error("No secret in post body found")
		return nil, nil
	}

	if len(id) > p.options.InputLengthRestrictions.ClientId {
		p.logger.Error("Client ID exceeds maximum length.")
		return nil, nil
	}

	if secret != "" {
		if len(secret) > p.options.InputLengthRestrictions.ClientSecret {
			p.logger.Error("Client secret exceeds maximum length.")
			return nil, nil
		}

		parsedSecret := &models.ParsedSecret{
			Id:         id,
			Credential: secret,
			Type:       gois.ParsedSecretTypesSharedSecret,
		}

		return parsedSecret, nil
	} else {
		// client secret is optional
		p.logger.Debug("client id without secret found")

		parsedSecret := &models.ParsedSecret{
			Id:   id,
			Type: gois.ParsedSecretTypesNoSecret,
		}

		return parsedSecret, nil
	}
}

// Returns the authentication method name that this parser implements
func (p *PostBodySecretParser) AuthenticationMethod() string {
	return gois.EndpointAuthenticationMethodsPostBody
}
