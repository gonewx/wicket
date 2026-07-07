// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	storage_models "github.com/gonewx/wicket/storage/models"
)

type StubRedirectUriValidator struct {
	isRedirectUriValid           bool
	isPostLogoutRedirectUriValid bool
}

func NewStubRedirectUriValidator() *StubRedirectUriValidator {
	return &StubRedirectUriValidator{}
}

func (v *StubRedirectUriValidator) IsRedirectUriValid(requestedUri string, client *storage_models.Client) bool {
	return v.isRedirectUriValid
}

func (v *StubRedirectUriValidator) IsPostLogoutRedirectUriValid(requestedUri string, client *storage_models.Client) bool {
	return v.isPostLogoutRedirectUriValid
}

func (v *StubRedirectUriValidator) SetIsRedirectUriValid(isRedirectUriValid bool) {
	v.isRedirectUriValid = isRedirectUriValid
}

func (v *StubRedirectUriValidator) SetIsPostLogoutRedirectUriValid(isPostLogoutRedirectUriValid bool) {
	v.isPostLogoutRedirectUriValid = isPostLogoutRedirectUriValid
}
