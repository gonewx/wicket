// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package phoneverify

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Category sentinels. Consumers classify a failure with errors.Is and pull the
// vendor detail out with errors.As.
var (
	// ErrInvalidCredential means the supplied authentication token was
	// rejected. Unrecognised vendor codes also land here so an unknown
	// response can never be mistaken for a transient condition and retried
	// into an accidental acceptance.
	ErrInvalidCredential = errors.New("phoneverify: invalid credential")

	// ErrRetryable means the exchange failed for a condition that may clear
	// on its own: transport failure, upstream 5xx, provider busy or rate
	// limited.
	ErrRetryable = errors.New("phoneverify: retryable failure")

	// ErrMalformedResponse means the exchange completed but the payload did
	// not carry a usable phone number.
	ErrMalformedResponse = errors.New("phoneverify: malformed response")

	// ErrUnavailable means this side cannot serve the exchange at all: the
	// credentials are missing or invalid, the endpoint is unusable, or the
	// provider reports that this account lacks permission or subscription.
	ErrUnavailable = errors.New("phoneverify: verifier unavailable")
)

// Vendor return codes recognised by lookupVendorCode.
//
// Matching is on the exact string. Grouping by prefix is deliberately avoided:
// the vendor's per-caller prefix covers both codes that mean "the user's token
// is no good" and codes that mean "this account is not permitted to ask", and
// those two require opposite treatment. A prefix rule would necessarily merge
// them.
const (
	codeSuccess = "OK"

	// Codes that mean the presented token is not usable.
	codeTokenInvalid          = "isv.TOKEN_INVALID"
	codeTokenUnauthorizedUsed = "isv.TOKEN_UNAUTHORIZED_USED"
	codeTokenExpired          = "InvalidBizToken.Expired"
	codeTokenCheckFailed      = "InvalidBizToken.Check"
	codeRetrievalFailed       = "GET_MOBILE_FAILED"

	// Codes that mean this side's credentials or subscription are at fault.
	codePermissionDenied    = "isv.RAM_PERMISSION_DENY"
	codeForbiddenAction     = "isv.FORBIDDEN_ACTION"
	codeProductUnsubscribed = "isv.PRODUCT_UNSUBSCRIBE"
	codeSchemeNotFound      = "isv.VERIFY_SCHEME_NOT_EXIST"
	codeSignatureMismatch   = "SignatureDoesNotMatch"
	codeSignatureIncomplete = "IncompleteSignature"

	// Codes that mean the condition may clear on its own.
	codeRateLimited     = "isp.QPS_LIMIT"
	codeBusinessLimited = "isv.BUSINESS_LIMIT_CONTROL"
	codeSystemError     = "isp.SYSTEM_ERROR"
	codeUnknownError    = "isp.UNKNOWN"
)

// SDK-reported failure codes this package distinguishes. These are produced by
// the client library itself rather than by the provider.
const (
	codeDecodeFailure = "SDK.JsonUnmarshalError"
	codeTimeout       = "SDK.TimeoutError"
)

// VendorError carries the provider's raw return code, message, request
// identifier and HTTP status alongside a category sentinel, so a consumer can
// branch on the category yet still log or surface the original detail.
type VendorError struct {
	// Code is the provider's return code, verbatim.
	Code string

	// Message is the provider's message text, redacted. The provider is not
	// expected to echo this side's credentials back, but this text reaches
	// callers and every such path in this package is redacted rather than
	// trusted.
	Message string

	// RequestID is the provider's request identifier, for reconciliation and
	// support tickets. It may be empty when the failure carried none.
	RequestID string

	// HTTPStatus is the transport status the failure arrived under. It is
	// zero when the failure did not come from a response, and 200 when the
	// provider reported a business failure under a success status.
	HTTPStatus int

	// category is the sentinel this failure maps to.
	category error
}

func (e *VendorError) Error() string {
	return fmt.Sprintf("phoneverify: provider returned code %s (status %d, request %s): %s",
		e.Code, e.HTTPStatus, e.RequestID, e.Message)
}

// Unwrap exposes the category sentinel so errors.Is(err, ErrInvalidCredential)
// and errors.As(err, &vendorErr) both hold for the same value.
func (e *VendorError) Unwrap() error { return e.category }

// lookupVendorCode maps a provider return code onto a category sentinel,
// reporting whether the code was recognised at all. A caller that also holds a
// transport status uses the unrecognised case to fall back to that status.
//
// Comparison is exact-match by design; see the code constants above.
func lookupVendorCode(code string) (error, bool) {
	switch code {
	case codeTokenInvalid, codeTokenUnauthorizedUsed, codeTokenExpired,
		codeTokenCheckFailed, codeRetrievalFailed:
		return ErrInvalidCredential, true

	case codePermissionDenied, codeForbiddenAction, codeProductUnsubscribed,
		codeSchemeNotFound, codeSignatureMismatch, codeSignatureIncomplete:
		// These say nothing about the user's token: they say this side's
		// credentials, permissions or subscription are at fault. Reporting
		// them as an invalid credential would answer a perfectly ordinary
		// user with a rejection and hide an operational fault behind it.
		// Unavailable is still a closed posture — nobody is let through —
		// while naming the right cause.
		return ErrUnavailable, true

	case codeRateLimited, codeBusinessLimited, codeSystemError, codeUnknownError:
		return ErrRetryable, true

	default:
		return nil, false
	}
}

// classifyVendorCode maps a provider return code onto a category sentinel.
// Unrecognised codes deliberately land on ErrInvalidCredential: refusing an
// ambiguous response is the safe default.
func classifyVendorCode(code string) error {
	if category, ok := lookupVendorCode(code); ok {
		return category
	}
	return ErrInvalidCredential
}

// classifyHTTPStatus categorises a failure whose return code was not
// recognised, using the transport status as the only remaining signal. Anything
// not identifiably transient is refused.
func classifyHTTPStatus(status int) error {
	switch {
	case status >= http.StatusInternalServerError,
		status == http.StatusTooManyRequests,
		status == http.StatusRequestTimeout:
		return ErrRetryable
	default:
		return ErrInvalidCredential
	}
}

// redactionPlaceholder replaces a credential wherever it would otherwise reach
// a caller.
const redactionPlaceholder = "[REDACTED]"

// maxErrorTextBytes bounds how much provider- or transport-controlled text is
// echoed back in an error. That text is not this package's to size.
const maxErrorTextBytes = 256

// redactSecrets strips every occurrence of each secret from s.
//
// Each secret is stripped in both the form it was configured in and the form it
// takes once query-encoded. Those two differ whenever the secret contains a
// character the encoder escapes, and the encoded form is what appears in a
// transport error — matching only the configured form would let exactly the
// text this function exists to remove pass through untouched.
func redactSecrets(s string, secrets ...string) string {
	out := s
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		out = strings.ReplaceAll(out, secret, redactionPlaceholder)
		if encoded := url.QueryEscape(secret); encoded != secret {
			out = strings.ReplaceAll(out, encoded, redactionPlaceholder)
		}
	}
	return out
}

// truncate caps s at n bytes, marking the cut so a reader can tell the text is
// incomplete. The cut is pulled back to a rune boundary, because text carrying
// non-ASCII characters would otherwise leave a partial sequence in an error
// destined for a log or a JSON payload.
//
// Callers must redact before truncating, never the other way round: cutting
// first can split a secret, and a fragment no longer matches the text being
// searched for, so the surviving prefix would escape untouched.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	cut := s[:n]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return strings.ToValidUTF8(cut, "") + "..."
}

// secretDisplay reports a credential's presence without revealing its value.
func secretDisplay(secret string) string {
	if secret == "" {
		return ""
	}
	return redactionPlaceholder
}
