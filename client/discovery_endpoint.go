// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package client

import (
	"net/url"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/utils"
)

// From : IdentityModel/src/Client/DiscoveryEndpoint.cs
// DiscoveryEndpoint Represents a URL to a discovery endpoint - parsed to separate the URL and authority
type DiscoveryEndpoint struct {
	Url       string
	Authority string
}

func ParseUrl(input string, path string) (*DiscoveryEndpoint, error) {
	if path == "" {
		path = gois.DiscoveryDiscoveryEndpoint
	}

	uri, err := url.Parse(input)
	if err != nil {
		return nil, gois.InvalidOperationException
	}

	if !IsValidScheme(uri) {
		return nil, gois.InvalidOperationException
	}

	u := utils.RemoveTrailingSlash(input)
	if strings.HasPrefix(u, "/") {
		u = strings.TrimPrefix(u, "/")
	}

	if strings.HasSuffix(strings.ToLower(uri.String()), strings.ToLower(path)) {
		return &DiscoveryEndpoint{
			Url:       strings.TrimSuffix(u, path),
			Authority: u,
		}, nil
	}

	return &DiscoveryEndpoint{
		Url:       u,
		Authority: utils.EnsureTrailingSlash(u) + path,
	}, nil
}

func IsValidScheme(uri *url.URL) bool {
	return uri.Scheme == "http" || uri.Scheme == "https"
}
