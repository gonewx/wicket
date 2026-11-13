// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
)

// / Uses the registered secret parsers to parse a secret on the current request
type SecretParser struct {
	logger  *slog.Logger
	parsers []validators.SecretParser
}

// / Initializes a new instance of the <see cref="SecretParser"/> class.
// / <param name="parsers">The parsers.</param>
// / <param name="logger">The logger.</param>
func NewSecretParser(parsers []validators.SecretParser, logger *slog.Logger) *SecretParser {
	return &SecretParser{
		parsers: parsers,
		logger:  logger,
	}
}

// / Checks the context to find a secret.
func (p *SecretParser) Parse(request *http.Request) (*models.ParsedSecret, error) {
	// see if a registered parser finds a secret on the request
	var bestSecret *models.ParsedSecret
	for _, parser := range p.parsers {
		parsedSecret, err := parser.Parse(request)
		if err != nil {
			return nil, err
		}
		if parsedSecret != nil {
			p.logger.Debug("Parser found secret", slog.String("type", fmt.Sprintf("%T", parsedSecret)))

			bestSecret = parsedSecret

			if parsedSecret.Type != wicket.ParsedSecretTypesNoSecret {
				break
			}
		}
	}

	if bestSecret != nil {
		p.logger.Debug("Secret id found", slog.String("id", bestSecret.Id))
		return bestSecret, nil
	}

	p.logger.Debug("Parser found no secret")
	return nil, nil
}

// / Gets all available authentication methods.
func (p *SecretParser) GetAvailableAuthenticationMethods() []string {
	return utils.Where(
		utils.Select(p.parsers, func(x validators.SecretParser) string {
			return x.AuthenticationMethod()
		}), func(x string) bool {
			return strings.TrimSpace(x) != ""
		})
}
