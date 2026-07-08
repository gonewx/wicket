// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

import (
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
)

type BackchannelAuthenticationRequestValidationResult struct {
	*ValidationResult
	Request   *storage_models.BackchannelAuthenticationRequest
	ExpiresIn int
	Interval  int
}

func NewBackchannelAuthenticationRequestValidationResult() *BackchannelAuthenticationRequestValidationResult {
	return &BackchannelAuthenticationRequestValidationResult{ValidationResult: NewValidationResult()}
}

func NewBackchannelAuthenticationRequestValidationError(err error, description string) *BackchannelAuthenticationRequestValidationResult {
	result := NewBackchannelAuthenticationRequestValidationResult()
	result.Error = err
	result.Description = description
	return result
}

type BackchannelAuthenticationRequestIdValidationContext struct {
	RequestId string
	Request   *ValidatedTokenRequest
	Result    *TokenRequestValidationResult
}

type BackchannelAuthenticationUserValidationContext struct {
	LoginHint      string
	IdTokenHint    string
	LoginHintToken string
	Client         *storage_models.Client
	Subject        *claims.ClaimsPrincipal
}

func NewBackchannelAuthenticationRequestIdValidationError(request *ValidatedTokenRequest, err error, description string) *TokenRequestValidationResult {
	return NewTokenRequestValidationResult(request,
		WithTokenRequestValidationResultError(err),
		WithTokenRequestValidationResultDescription(description),
	)
}

func NewBackchannelAuthenticationRequestIdValidationSuccess(request *ValidatedTokenRequest) *TokenRequestValidationResult {
	return NewTokenRequestValidationResult(request)
}

var _ = gois.TokenErrorsInvalidGrant
