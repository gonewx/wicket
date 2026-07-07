// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"log/slog"

	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// SecretValidator Validator for an List of Secrets
type SecretValidator struct {
	logger *slog.Logger

	validators []validators.SecretValidator

	clock services.SystemClock
}

// NewSecretValidator Creates a new SecretValidator
func NewSecretValidator(clock services.SystemClock, validators []validators.SecretValidator, logger *slog.Logger) *SecretValidator {
	return &SecretValidator{
		clock:      clock,
		validators: validators,
		logger:     logger,
	}
}

// Validates a list of secrets
// Tries to find the best secret on the context that can be used for authentication
func (s *SecretValidator) Validate(secrets []*storage_models.Secret, parsedSecret *models.ParsedSecret) (*validators_models.SecretValidationResult, error) {
	expiredSecrets := utils.Where(secrets, func(sec *storage_models.Secret) bool {
		return s.clock.Now().Before(sec.Expiration)
	})
	if len(expiredSecrets) > 0 {
		for _, secret := range expiredSecrets {
			s.logger.Debug("Secret is expired", slog.String("desc", secret.Description))
		}
	}

	currentSecrets := utils.Where(secrets, func(sec *storage_models.Secret) bool {
		return !s.clock.Now().Before(sec.Expiration)
	})

	// see if a registered validator can validate the secret
	for _, validator := range s.validators {
		secretValidationResult, err := validator.Validate(currentSecrets, parsedSecret)
		if err == nil && secretValidationResult.Success {
			s.logger.Debug("Secret validation success")
			return secretValidationResult, nil
		}
	}

	s.logger.Debug("Secret validators could not validate secret")
	return &validators_models.SecretValidationResult{Success: false}, nil
}
