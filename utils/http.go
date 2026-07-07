// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package utils

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gonewx/wicket/claims"
)

func RemoveTrailingSlash(value string) string {
	return strings.TrimRight(value, "/")
}

func EnsureTrailingSlash(value string) string {
	if value == "" || strings.HasSuffix(value, "/") {
		return value
	}
	return value + "/"
}

func EnsureLeadingSlash(value string) string {
	if value == "" || strings.HasPrefix(value, "/") {
		return value
	}
	return "/" + value
}

func CleanUrlPath(value string) string {
	if value == "" {
		return ""
	}
	return "/" + strings.Trim(value, "/")
}

func IsLocalUrl(value string) bool {
	return strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~/")
}

func IsUri(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func AddQuery(uri string, key string, value string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func AddQueryString(uri string, values any) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	q := u.Query()
	for key, vals := range normalizeValues(values) {
		for _, value := range vals {
			q.Add(key, value)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func AddHashFragment(uri string, values any) string {
	encoded := normalizeValues(values).Encode()
	if encoded == "" {
		return uri
	}
	if strings.Contains(uri, "#") {
		return uri + "&" + encoded
	}
	return uri + "#" + encoded
}

func normalizeValues(values any) url.Values {
	switch v := values.(type) {
	case url.Values:
		return v
	case string:
		parsed, err := url.ParseQuery(v)
		if err != nil {
			return url.Values{}
		}
		return parsed
	default:
		return url.Values{}
	}
}

func GetAbsoluteUrl(baseURL string, local string) string {
	if IsUri(local) {
		return local
	}
	return EnsureTrailingSlash(RemoveTrailingSlash(baseURL)) + strings.TrimLeft(local, "/")
}

func ParseScopesString(value string) []string {
	return Where(strings.Fields(value), func(scope string) bool { return scope != "" })
}

func AreValidResourceGapFormat(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

func ToClaimsMap(items []*claims.Claim) map[string]any {
	out := make(map[string]any, len(items))
	for _, claim := range items {
		if claim != nil {
			out[claim.Type] = claim.Value
		}
	}
	return out
}

func AppBasePath() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return filepath.Clean(wd)
}
