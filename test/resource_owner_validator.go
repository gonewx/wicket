// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package test

import (
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/services"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// TestUserResourceOwnerPasswordValidator validates test users against TestUserStore.
// input: username/password -> behavior: match configured test user credentials -> output: grant validation result.
type TestUserResourceOwnerPasswordValidator struct {
	store *TestUserStore
	clock services.SystemClock
}

func NewTestUserResourceOwnerPasswordValidator(store *TestUserStore, clock services.SystemClock) *TestUserResourceOwnerPasswordValidator {
	return &TestUserResourceOwnerPasswordValidator{store: store, clock: clock}
}

func (v *TestUserResourceOwnerPasswordValidator) Validate(ctx *validators_contexts.ResourceOwnerPasswordValidationContext) error {
	if ctx == nil || v.store == nil || !v.store.ValidateCredentials(ctx.UserName, ctx.Password) {
		return nil
	}

	user := v.store.FindByUsername(ctx.UserName)
	subject := ctx.UserName
	if user != nil && user.SubjectId != "" {
		subject = user.SubjectId
	}

	now := time.Now()
	if v.clock != nil {
		now = v.clock.Now()
	}

	ctx.Result = validators_models.NewGrantValidationResult(
		validators_models.WithGrantValidationResultSubject(subject, "password", now, nil, gois.LocalIdentityProvider, nil),
	)
	return nil
}
