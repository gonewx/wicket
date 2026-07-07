// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package extensions

import (
	"fmt"
	"log/slog"

	"github.com/gonewx/wicket"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

func ToValidationResult(client *storage_models.Client, secret *models.ParsedSecret) *validators_models.ClientSecretValidationResult {
	return &validators_models.ClientSecretValidationResult{
		Client: client,
		Secret: secret,
	}
}

func ValidateOptions(options *config_options.WicketOptions, logger *slog.Logger) error {
	if options.IssuerUri == "" {
		logger.Debug("Custom IssuerUri set ", slog.String("issuerUri", options.IssuerUri))
	}

	// todo: perhaps different logging messages?
	//if (options.UserInteraction.LoginUrl.IsMissing()) throw new InvalidOperationException("LoginUrl is not configured");
	//if (options.UserInteraction.LoginReturnUrlParameter.IsMissing()) throw new InvalidOperationException("LoginReturnUrlParameter is not configured");
	//if (options.UserInteraction.LogoutUrl.IsMissing()) throw new InvalidOperationException("LogoutUrl is not configured");
	if options.UserInteraction.LogoutIdParameter == "" {
		return fmt.Errorf("%w : LogoutIdParameter is not configured", gois.InvalidOperationException)
	}
	if options.UserInteraction.ErrorUrl == "" {
		return fmt.Errorf("%w : ErrorUrl is not configured", gois.InvalidOperationException)
	}
	if options.UserInteraction.ErrorIdParameter == "" {
		return fmt.Errorf("%w : ErrorIdParameter is not configured", gois.InvalidOperationException)
	}
	if options.UserInteraction.ConsentUrl == "" {
		return fmt.Errorf("%w : ConsentUrl is not configured", gois.InvalidOperationException)
	}
	if options.UserInteraction.ConsentReturnUrlParameter == "" {
		return fmt.Errorf("%w : ConsentReturnUrlParameter is not configured", gois.InvalidOperationException)
	}
	if options.UserInteraction.CustomRedirectReturnUrlParameter == "" {
		return fmt.Errorf("%w : CustomRedirectReturnUrlParameter is not configured", gois.InvalidOperationException)
	}

	if options.Authentication.CheckSessionCookieName == "" {
		return fmt.Errorf("%w : CheckSessionCookieName is not configured", gois.InvalidOperationException)
	}

	if options.Cors.CorsPolicyName == "" {
		return fmt.Errorf("%w : CorsPolicyName is not configured", gois.InvalidOperationException)
	}

	return nil
}
