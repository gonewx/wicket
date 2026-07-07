// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

type StrictRedirectUriValidator struct {
}

func NewStrictRedirectUriValidator() *StrictRedirectUriValidator {
	return &StrictRedirectUriValidator{}
}

func (v *StrictRedirectUriValidator) contains(uris []string, requestedUri string) bool {
	if len(uris) == 0 {
		return false
	}

	return utils.Contains(uris, requestedUri)
}

func (v *StrictRedirectUriValidator) IsRedirectUriValid(requestedUri string, client *storage_models.Client) bool {
	return v.contains(client.RedirectUris, requestedUri)
}

func (v *StrictRedirectUriValidator) IsPostLogoutRedirectUriValid(requestedUri string, client *storage_models.Client) bool {
	return v.contains(client.PostLogoutRedirectUris, requestedUri)
}
