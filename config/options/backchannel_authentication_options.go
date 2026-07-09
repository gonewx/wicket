// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package options

import (
	"net/http"
	"time"
)

type BackchannelAuthenticationOptions struct {
	Enabled                    bool
	AllowedDeliveryModes       []string
	DefaultRequestLifetime     int
	DefaultPollingInterval     int
	SlowDownIntervalIncrement  int
	UserCodeParameterSupported bool
}

func NewBackchannelAuthenticationOptions() *BackchannelAuthenticationOptions {
	return &BackchannelAuthenticationOptions{
		Enabled:                    true,
		AllowedDeliveryModes:       []string{"poll"},
		DefaultRequestLifetime:     300,
		DefaultPollingInterval:     5,
		SlowDownIntervalIncrement:  5,
		UserCodeParameterSupported: true,
	}
}

type MutualTlsOptions struct {
	Enabled    bool
	DomainName string
}

func NewMutualTlsOptions() *MutualTlsOptions {
	return &MutualTlsOptions{Enabled: false}
}

type DynamicProviderOptions struct {
	Enabled bool
}

func NewDynamicProviderOptions() *DynamicProviderOptions {
	return &DynamicProviderOptions{Enabled: false}
}

type ServerSideSessionOptions struct {
	Enabled         bool
	SessionLifetime time.Duration
	CookieName      string
	// CookieSecure marks the session cookie Secure so browsers only send it
	// over TLS. Defaults to true: all user-facing OIDC endpoints require TLS
	// (OIDC Core 1.0 §16.17). Override to false only for plain-HTTP local
	// development.
	CookieSecure bool
	// CookieSameSite controls the session cookie SameSite attribute. Defaults
	// to None so the cookie is sent when the OP authorize endpoint is loaded
	// in a cross-site hidden iframe during silent renew (OIDC Session
	// Management 1.0). None requires Secure to be set. Deployments without
	// iframe-based renew may tighten this to Lax.
	CookieSameSite http.SameSite
}

func NewServerSideSessionOptions() *ServerSideSessionOptions {
	return &ServerSideSessionOptions{
		Enabled:         false,
		SessionLifetime: 14 * 24 * time.Hour,
		CookieName:      "wicket.session",
		CookieSecure:    true,
		CookieSameSite:  http.SameSiteNoneMode,
	}
}
