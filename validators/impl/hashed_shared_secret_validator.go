// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	validtors_models "github.com/gonewx/wicket/validators/models"
)

// HashedSharedSecretValidator Validates a shared secret stored in SHA256 or SHA512
type HashedSharedSecretValidator struct {
	logger *slog.Logger
}

func NewHashedSharedSecretValidator(logger *slog.Logger) *HashedSharedSecretValidator {
	return &HashedSharedSecretValidator{
		logger: logger,
	}
}

// Validate Validates a secret
func (s *HashedSharedSecretValidator) Validate(secrets []*storage_models.Secret, parsedSecret *models.ParsedSecret) (*validtors_models.SecretValidationResult, error) {
	fail := &validtors_models.SecretValidationResult{Success: false}
	success := &validtors_models.SecretValidationResult{Success: true}

	if parsedSecret.Type != wicket.ParsedSecretTypesSharedSecret {
		s.logger.Debug("Hashed shared secret validator cannot process", slog.String("type", parsedSecret.Type))
		return fail, nil
	}

	sharedSecrets := utils.Where(secrets, func(s *storage_models.Secret) bool {
		return s.Type == wicket.ParsedSecretTypesSharedSecret
	})
	if len(sharedSecrets) == 0 {
		s.logger.Debug("No shared secret configured for client.")
		return fail, nil
	}

	sharedSecret := parsedSecret.Credential

	if parsedSecret.Id == "" || sharedSecret == "" {
		return nil, fmt.Errorf("Id or Credential is missing.")
	}

	secretSha256 := utils.Sha256(sharedSecret)
	secretSha512 := utils.Sha512(sharedSecret)

	for _, secret := range sharedSecrets {
		secretDescription := secret.Description
		if secret.Description == "" {
			secretDescription = "no description"
		}

		isValid := false
		secretBytes, err := base64.StdEncoding.DecodeString(secret.Value)
		if err != nil {
			s.logger.Info("Secret: uses invalid hashing algorithm.", slog.String("description", secretDescription))
			return fail, nil
		}

		if secretBytes == nil {
			s.logger.Info("Secret: is null", slog.String("description", secretDescription))
			return fail, nil
		}

		if len(secretBytes) == 32 {
			isValid = utils.TimeConstantCompare(secret.Value, secretSha256)
		} else {
			if len(secretBytes) == 64 {
				isValid = utils.TimeConstantCompare(secret.Value, secretSha512)
			} else {
				s.logger.Info("Secret: uses invalid hashing algorithm.", slog.String("description", secretDescription))
				return fail, nil
			}
		}

		if isValid {
			return success, nil
		}
	}

	s.logger.Debug("No matching hashed secret found.")
	return fail, nil
}
