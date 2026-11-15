// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

import (
	"net/url"
	"strings"
)

// ClientThirdPartyLoginMetadata is the metadata a client registers so that a
// third party can initiate its login with this server (OpenID Connect Core
// 1.0 section 4). The zero value means the client registers no login
// initiation endpoint.
type ClientThirdPartyLoginMetadata struct {
	// InitiateLoginUri is the client's login initiation endpoint. It
	// corresponds to the initiate_login_uri client metadata of OpenID Connect
	// Dynamic Client Registration 1.0 section 2. The empty string means none
	// is registered; any other value must be an absolute https URI with a
	// host (IsAbsoluteHttpsUri).
	InitiateLoginUri string
}

// IsAbsoluteHttpsUri reports whether raw parses as an absolute URI whose
// scheme is https, compared case-insensitively, whose host is not empty and
// whose query, if any, parses as name/value pairs.
func IsAbsoluteHttpsUri(raw string) bool {
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if !parsed.IsAbs() || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return false
	}
	_, err = url.ParseQuery(parsed.RawQuery)
	return err == nil
}
