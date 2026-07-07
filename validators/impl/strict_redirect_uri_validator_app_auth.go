// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"strconv"
	"strings"

	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

type StrictRedirectUriValidatorAppAuth struct {
	base *StrictRedirectUriValidator
}

func (v *StrictRedirectUriValidatorAppAuth) IsRedirectUriValid(requestedUri string, client *storage_models.Client) bool {
	isAllowed := v.base.IsRedirectUriValid(requestedUri, client)
	if isAllowed {
		return isAllowed
	}

	// since this is appauth specific, we can require pkce
	if client.RequirePkce && utils.Contains(client.RedirectUris, "http://127.0.0.1") {
		return v.isLoopback(requestedUri)
	}

	return false
}

func (v *StrictRedirectUriValidatorAppAuth) IsPostLogoutRedirectUriValid(requestedUri string, client *storage_models.Client) bool {
	isAllowed := v.base.IsPostLogoutRedirectUriValid(requestedUri, client)
	if isAllowed {
		return isAllowed
	}

	// since this is appauth specific, we can require pkce
	if client.RequirePkce && utils.Contains(client.RedirectUris, "http://127.0.0.1") {
		return v.isLoopback(requestedUri)
	}

	return false
}

func (v *StrictRedirectUriValidatorAppAuth) isLoopback(requestedUri string) bool {
	if strings.TrimSpace(requestedUri) == "" {
		return false
	}

	parts := strings.Split(requestedUri, ":")
	if len(parts) != 3 {
		return false
	}

	if parts[0] != "http" || parts[1] != "//127.0.0.1" {
		return false
	}

	portStr := ""
	indexOfPathSeparator := strings.IndexAny(parts[2], "/?#")
	if indexOfPathSeparator == -1 {
		portStr = parts[2]
	} else {
		portStr = parts[2][:indexOfPathSeparator]
	}

	// Valid port range is 0 through 65535.
	port, err := strconv.ParseInt(portStr, 10, 0)
	if err != nil {
		return false
	}

	if port >= 0 && port < 65536 {
		return true
	}

	return false
}
