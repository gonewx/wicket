// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package wechatverify verifies a WeChat mobile-app login credential by
// exchanging it server-side for a stable user identifier.
//
// The package is a back-end capability only: it owns no HTTP handler, no
// cookie, and no redirect. A business back end hands it the authorization code
// its app obtained from the WeChat SDK and receives a verified identity in
// return, so the application secret never has to be distributed to every
// consuming system.
package wechatverify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// DefaultEndpoint is the mobile-app credential exchange endpoint. It is not
// the mini-program session endpoint; the two are different products with
// different response shapes.
const DefaultEndpoint = "https://api.weixin.qq.com/sns/oauth2/access_token"

// defaultTimeout bounds a single exchange when the caller supplies no client
// of its own.
const defaultTimeout = 10 * time.Second

// Verifier exchanges an authorization code for a verified identity.
type Verifier interface {
	Verify(ctx context.Context, code string) (*VerifiedIdentity, error)
}

// SubjectSource records which identifier Subject was taken from.
type SubjectSource string

const (
	// SubjectFromUnionID means Subject holds the cross-application
	// identifier, stable across every application under the same open
	// platform account.
	SubjectFromUnionID SubjectSource = "unionid"

	// SubjectFromOpenID means the cross-application identifier was absent
	// and Subject fell back to the per-application identifier. This is a
	// degraded identity: it is stable only within this one application.
	SubjectFromOpenID SubjectSource = "openid"
)

// VerifiedIdentity is the outcome of a successful exchange.
type VerifiedIdentity struct {
	// Subject is the identifier a consumer should key its user record on:
	// UnionID when present, OpenID otherwise.
	Subject string

	// SubjectSource states which of the two Subject came from, so a
	// consumer can detect and act on the degraded case.
	SubjectSource SubjectSource

	// UnionID is the raw cross-application identifier. It is returned only
	// when the application has user-info authorization and the account is
	// bound to an open platform account, so an empty value is a normal
	// outcome rather than an error.
	UnionID string

	// OpenID is the raw per-application identifier. Non-empty on success.
	OpenID string

	// Scope is the granted authorization scope, passed through verbatim.
	Scope string
}

// Config configures a Verifier.
type Config struct {
	// AppID is the mobile application identifier. Required.
	AppID string

	// AppSecret is the application secret. Required. It travels in the
	// request query string, which is why every error path in this package
	// is redacted before it reaches a caller.
	AppSecret string

	// Endpoint overrides DefaultEndpoint. Empty means DefaultEndpoint.
	Endpoint string

	// HTTPClient overrides the internally constructed client. When nil a
	// client bounded by Timeout is built instead.
	HTTPClient *http.Client

	// Timeout bounds the internally constructed client. Ignored when
	// HTTPClient is supplied. Zero means defaultTimeout.
	Timeout time.Duration
}

// String renders the configuration with the secret removed, so that printing a
// Config with %v or %+v cannot leak it.
func (c Config) String() string {
	return fmt.Sprintf("wechatverify.Config{AppID:%s, AppSecret:%s, Endpoint:%s}",
		c.AppID, secretDisplay(c.AppSecret), c.Endpoint)
}

// MarshalJSON renders the configuration with the secret removed. String covers
// only the fmt verbs; a Config reaching a structured encoder — directly, or as
// a field of something larger — would otherwise emit the secret in clear text.
// Decoding is deliberately left untouched, so a configuration can still be read
// from JSON; only the outbound direction is redacted.
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AppID     string `json:"AppID"`
		AppSecret string `json:"AppSecret"`
		Endpoint  string `json:"Endpoint"`
		Timeout   string `json:"Timeout"`
	}{
		AppID:     c.AppID,
		AppSecret: secretDisplay(c.AppSecret),
		Endpoint:  c.Endpoint,
		Timeout:   c.Timeout.String(),
	})
}

// LogValue renders the configuration with the secret removed. A structured
// logger reaches for this before it reflects over the fields, which is the
// path a consumer takes when it logs its own configuration.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("AppID", c.AppID),
		slog.String("AppSecret", secretDisplay(c.AppSecret)),
		slog.String("Endpoint", c.Endpoint),
	)
}

// validateEndpoint refuses an endpoint the exchange cannot be built from. The
// query string is appended to this value, so an endpoint that already carries
// one would bury the exchange parameters inside the last existing value rather
// than adding them; and a scheme the HTTP client cannot serve would surface
// only once a request was attempted. Both are configuration faults and are
// reported as such at assembly time.
//
// Plain http is accepted: the exchange has to be pointed at a local test server
// during development, and that server does not serve TLS.
func validateEndpoint(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("%w: endpoint is not a valid URL", ErrUnavailable)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: endpoint scheme %q is not http or https",
			ErrUnavailable, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: endpoint has no host", ErrUnavailable)
	}
	if parsed.RawQuery != "" {
		return fmt.Errorf("%w: endpoint must not carry a query string", ErrUnavailable)
	}
	return nil
}

// secretDisplay reports a secret's presence without revealing its value.
func secretDisplay(secret string) string {
	if secret == "" {
		return ""
	}
	return redactionPlaceholder
}

type verifier struct {
	appID     string
	appSecret string
	endpoint  string
	client    *http.Client
}

// String renders the verifier with the secret removed.
func (v *verifier) String() string {
	return fmt.Sprintf("wechatverify.Verifier{AppID:%s, AppSecret:%s, Endpoint:%s}",
		v.appID, secretDisplay(v.appSecret), v.endpoint)
}

// NewVerifier builds a Verifier. Missing credentials are refused at
// construction time rather than deferred to the first exchange, so a consumer
// that cannot serve WeChat logins learns it at assembly time and can hold a
// closed posture.
func NewVerifier(cfg Config) (Verifier, error) {
	if cfg.AppID == "" {
		return nil, fmt.Errorf("%w: application id is not configured", ErrUnavailable)
	}
	if cfg.AppSecret == "" {
		return nil, fmt.Errorf("%w: application secret is not configured", ErrUnavailable)
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}

	client := cfg.HTTPClient
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = defaultTimeout
		}
		client = &http.Client{
			Timeout: timeout,
			// The secret travels in the query string, and a followed
			// redirect puts the previous URL in the Referer header of the
			// request to the new host. Redirects are not part of this
			// exchange, so the response is surfaced as-is instead.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return &verifier{
		appID:     cfg.AppID,
		appSecret: cfg.AppSecret,
		endpoint:  endpoint,
		client:    client,
	}, nil
}
