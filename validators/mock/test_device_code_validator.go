// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	"context"
	"fmt"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type TestDeviceCodeValidator struct {
	shouldError bool

	DeviceCodeResult *storage_models.DeviceCode
}

func NewTestDeviceCodeValidator(shouldError bool) *TestDeviceCodeValidator {
	return &TestDeviceCodeValidator{
		shouldError:      shouldError,
		DeviceCodeResult: &storage_models.DeviceCode{},
	}
}

func (c *TestDeviceCodeValidator) Validate(ctx context.Context, validation *validators_models.DeviceCodeValidationContext) error {
	opts := make([]wicket.Option[validators_models.TokenRequestValidationResult], 0)
	if c.shouldError {
		opts = append(opts, validators_models.WithTokenRequestValidationResultError(fmt.Errorf("error")))
	}

	validation.Result = validators_models.NewTokenRequestValidationResult(
		validation.Request,
		opts...,
	)

	validation.Request.DeviceCode = c.DeviceCodeResult

	return nil
}
