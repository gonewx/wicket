// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package phoneverify verifies a one-tap phone-number login credential by
// exchanging it server-side for the phone number it stands for.
//
// The package is a back-end capability only: it owns no HTTP handler, no
// cookie, and no redirect. A business back end hands it the authentication
// token its app obtained from the vendor's mobile SDK and receives a verified
// phone number in return, so the account credentials and the cryptographic
// signing they drive stay in one place instead of being distributed to every
// consuming system.
package phoneverify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultEndpoint is the public service endpoint the exchange is issued
	// against.
	DefaultEndpoint = "https://dypnsapi.aliyuncs.com"

	// DefaultRegionID is the region the request is signed for. The service is
	// not region-partitioned for this operation, but the signing scheme
	// requires a region and refuses an empty one.
	DefaultRegionID = "cn-hangzhou"
)

// defaultTimeout bounds a single exchange when the caller configures none.
const defaultTimeout = 10 * time.Second

// Verifier exchanges an authentication token for a verified phone number.
type Verifier interface {
	Verify(ctx context.Context, token string) (*VerifiedPhone, error)
}

// VerifiedPhone is the outcome of a successful exchange.
type VerifiedPhone struct {
	// Mobile is the verified phone number. Non-empty on success. The value
	// is passed through exactly as the provider returned it; this package
	// applies no reformatting of its own.
	Mobile string

	// RequestID is the provider's request identifier, for reconciliation and
	// support tickets.
	RequestID string
}

// PhoneAuthConfig configures a Verifier.
type PhoneAuthConfig struct {
	// AppKey identifies the verification scheme registered in the vendor's
	// console. Required.
	//
	// It is not sent with the exchange: the operation invoked here takes no
	// such parameter, because the value addresses the mobile SDK's side of
	// the arrangement. It is still required here, so that a deployment
	// missing any part of its identity is refused as a whole rather than
	// failing later in the part that happens to be checked.
	AppKey string

	// AccessKeyID identifies the account the exchange is billed and
	// authorised against. Required. It travels in the request as part of the
	// signature, which is why the error paths in this package redact it
	// alongside the secret: there it sits inside a replayable signed URL. On
	// its own it is an account identifier rather than a secret, so the
	// configuration renderings leave it visible for operational use.
	AccessKeyID string

	// AccessKeySecret is the signing key. Required. It is never transmitted:
	// it keys the request signature and stays on this side.
	AccessKeySecret string

	// RegionID is the region the request is signed for. Empty means
	// DefaultRegionID.
	RegionID string

	// Endpoint overrides DefaultEndpoint. It is a complete URL; the scheme
	// and host are taken from it. Empty means DefaultEndpoint.
	Endpoint string

	// Timeout bounds a single exchange at the transport level. Any value at
	// or below zero means defaultTimeout.
	Timeout time.Duration
}

// String renders the configuration with the secret removed, so that printing a
// PhoneAuthConfig with %v or %+v cannot leak it. The receiver is a value, so a
// configuration held by value — or inside a slice or map — is covered too.
func (c PhoneAuthConfig) String() string {
	return fmt.Sprintf("phoneverify.PhoneAuthConfig{AppKey:%s, AccessKeyID:%s, AccessKeySecret:%s, RegionID:%s, Endpoint:%s, Timeout:%s}",
		c.AppKey, c.AccessKeyID, secretDisplay(c.AccessKeySecret),
		c.RegionID, c.Endpoint, c.Timeout)
}

// MarshalJSON renders the configuration with the secret removed. String covers
// only the fmt verbs; a configuration reaching a structured encoder — directly,
// or as a field of something larger — would otherwise emit the secret in clear
// text. Decoding is deliberately left untouched, so a configuration can still
// be read from JSON; only the outbound direction is redacted.
func (c PhoneAuthConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		AppKey          string `json:"AppKey"`
		AccessKeyID     string `json:"AccessKeyID"`
		AccessKeySecret string `json:"AccessKeySecret"`
		RegionID        string `json:"RegionID"`
		Endpoint        string `json:"Endpoint"`
		Timeout         string `json:"Timeout"`
	}{
		AppKey:          c.AppKey,
		AccessKeyID:     c.AccessKeyID,
		AccessKeySecret: secretDisplay(c.AccessKeySecret),
		RegionID:        c.RegionID,
		Endpoint:        c.Endpoint,
		Timeout:         c.Timeout.String(),
	})
}

// GoString mirrors String, so the %#v verb — which consults GoString rather
// than String — cannot leak the secret either.
func (c PhoneAuthConfig) GoString() string { return c.String() }

// LogValue renders the configuration with the secret removed. A structured
// logger reaches for this before it reflects over the fields, which is the path
// a consumer takes when it logs its own configuration.
func (c PhoneAuthConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("AppKey", c.AppKey),
		slog.String("AccessKeyID", c.AccessKeyID),
		slog.String("AccessKeySecret", secretDisplay(c.AccessKeySecret)),
		slog.String("RegionID", c.RegionID),
		slog.String("Endpoint", c.Endpoint),
		slog.String("Timeout", c.Timeout.String()),
	)
}

type verifier struct {
	appKey          string
	accessKeyID     string
	accessKeySecret string
	regionID        string

	// scheme and host are the endpoint split into the two pieces the request
	// carries separately.
	scheme string
	host   string

	timeout time.Duration
}

// String renders the verifier with the secret removed.
func (v *verifier) String() string {
	return fmt.Sprintf("phoneverify.Verifier{AppKey:%s, AccessKeyID:%s, AccessKeySecret:%s, RegionID:%s, Endpoint:%s://%s}",
		v.appKey, v.accessKeyID, secretDisplay(v.accessKeySecret),
		v.regionID, v.scheme, v.host)
}

// GoString mirrors String for the %#v verb.
func (v *verifier) GoString() string { return v.String() }

// NewVerifier builds a Verifier. Missing credentials are refused at
// construction time rather than deferred to the first exchange, so a consumer
// that cannot serve one-tap logins learns it at assembly time and can hold a
// closed posture from the start.
func NewVerifier(cfg PhoneAuthConfig) (Verifier, error) {
	// A value of nothing but whitespace configures nothing; it is refused the
	// same as an absent one, rather than carried along to fail as a signature
	// error on the first exchange.
	if strings.TrimSpace(cfg.AppKey) == "" {
		return nil, fmt.Errorf("%w: application key is not configured", ErrUnavailable)
	}
	if strings.TrimSpace(cfg.AccessKeyID) == "" {
		return nil, fmt.Errorf("%w: access key id is not configured", ErrUnavailable)
	}
	if strings.TrimSpace(cfg.AccessKeySecret) == "" {
		return nil, fmt.Errorf("%w: access key secret is not configured", ErrUnavailable)
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	scheme, host, err := splitEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	regionID := cfg.RegionID
	if regionID == "" {
		regionID = DefaultRegionID
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &verifier{
		appKey:          cfg.AppKey,
		accessKeyID:     cfg.AccessKeyID,
		accessKeySecret: cfg.AccessKeySecret,
		regionID:        regionID,
		scheme:          scheme,
		host:            host,
		timeout:         timeout,
	}, nil
}

// splitEndpoint takes an endpoint apart into the scheme and the host the
// request carries as separate values, refusing shapes the exchange cannot be
// built from. A scheme the client cannot serve, or a missing host, would
// otherwise surface only once a request was attempted; a query string, a
// path, a fragment or embedded credentials would be silently dropped, since
// the exchange builds its own request line from the host alone — a proxy
// configured as https://host/prefix would quietly be called at the root
// instead. All of these are configuration faults and are reported as such at
// assembly time.
//
// Plain http is accepted: the exchange has to be pointed at a local server
// during development, and that server does not serve TLS. The host keeps its
// port for the same reason.
func splitEndpoint(endpoint string) (scheme, host string, err error) {
	parsed, parseErr := url.Parse(endpoint)
	if parseErr != nil {
		return "", "", fmt.Errorf("%w: endpoint is not a valid URL", ErrUnavailable)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", fmt.Errorf("%w: endpoint scheme %q is not http or https",
			ErrUnavailable, parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", "", fmt.Errorf("%w: endpoint has no host", ErrUnavailable)
	}
	if parsed.User != nil {
		return "", "", fmt.Errorf("%w: endpoint must not carry credentials", ErrUnavailable)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", "", fmt.Errorf("%w: endpoint must not carry a path", ErrUnavailable)
	}
	if parsed.RawQuery != "" {
		return "", "", fmt.Errorf("%w: endpoint must not carry a query string", ErrUnavailable)
	}
	if parsed.Fragment != "" {
		return "", "", fmt.Errorf("%w: endpoint must not carry a fragment", ErrUnavailable)
	}
	return parsed.Scheme, parsed.Host, nil
}

// redact removes this verifier's credentials — and any extra per-call values,
// such as the token being verified — from text bound for a caller, then strips
// the signing parameters' values. The secret never travels, but the key id and
// the token do — both are part of the signed request URL a transport error
// embeds — so all of them are stripped.
func (v *verifier) redact(s string, extras ...string) string {
	secrets := append([]string{v.accessKeySecret, v.accessKeyID}, extras...)
	return redactSignedQueryValues(redactSecrets(s, secrets...))
}
