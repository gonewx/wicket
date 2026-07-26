// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wechatverify

import (
	"errors"
	"fmt"
	"strings"
)

// Category sentinels. Consumers classify a failure with errors.Is and pull the
// vendor detail out with errors.As.
var (
	// ErrInvalidCredential means the supplied code (or the configured
	// application identity) was rejected by the provider. Unknown vendor
	// codes also land here so an unrecognised response can never be mistaken
	// for a transient condition and retried into an accidental success.
	ErrInvalidCredential = errors.New("wechatverify: invalid credential")

	// ErrRetryable means the exchange failed for a condition that may clear
	// on its own: transport failure, upstream 5xx, provider busy or rate
	// limited.
	ErrRetryable = errors.New("wechatverify: retryable failure")

	// ErrMalformedResponse means the exchange completed but the payload did
	// not carry a usable identity.
	ErrMalformedResponse = errors.New("wechatverify: malformed response")

	// ErrUnavailable means the verifier is not configured and cannot serve
	// requests at all.
	ErrUnavailable = errors.New("wechatverify: verifier unavailable")
)

// Vendor return codes recognised by classifyVendorCode. Matching is on the
// integer value, never on the message text — the provider's wording is not a
// stable contract.
const (
	codeSystemBusy       = -1
	codeInvalidAppID     = 40013
	codeInvalidAppSecret = 40125
	codeInvalidCredsPair = 40001
	codeInvalidCode      = 40029
	codeCodeAlreadyUsed  = 40163
	codeMissingCode      = 41008
	codeRateLimited      = 45011
)

// VendorError carries the provider's raw return code and message alongside a
// category sentinel, so a consumer can branch on the category yet still log or
// surface the original detail.
type VendorError struct {
	// Code is the provider's numeric return code.
	Code int
	// Msg is the provider's message text, verbatim.
	Msg string
	// category is the sentinel this code maps to.
	category error
}

func (e *VendorError) Error() string {
	return fmt.Sprintf("wechatverify: provider returned errcode %d: %s", e.Code, e.Msg)
}

// Unwrap exposes the category sentinel so errors.Is(err, ErrInvalidCredential)
// and errors.As(err, &vendorErr) both hold for the same value.
func (e *VendorError) Unwrap() error { return e.category }

// classifyVendorCode maps a provider return code onto a category sentinel.
// Unrecognised non-zero codes deliberately fall through to
// ErrInvalidCredential: refusing an ambiguous response is the safe default.
func classifyVendorCode(code int) error {
	switch code {
	case codeSystemBusy, codeRateLimited:
		return ErrRetryable
	case codeInvalidAppID, codeInvalidAppSecret, codeInvalidCredsPair,
		codeInvalidCode, codeCodeAlreadyUsed, codeMissingCode:
		return ErrInvalidCredential
	default:
		return ErrInvalidCredential
	}
}

// redactionPlaceholder replaces the application secret wherever it would
// otherwise reach a caller.
const redactionPlaceholder = "[REDACTED]"

// redactSecret strips every occurrence of secret from s. The request URL
// carries the secret as a query parameter, so any text derived from a
// transport error, a response echo, or a struct dump must pass through here
// before it leaves the package.
func redactSecret(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, redactionPlaceholder)
}
