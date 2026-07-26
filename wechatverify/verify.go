// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wechatverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// maxErrorBodyBytes bounds how much of an unparseable body is echoed back in an
// error. The body is provider-controlled text; quoting it wholesale would make
// the error unbounded.
const maxErrorBodyBytes = 256

// maxResponseBytes bounds how much of a response is read at all. The endpoint
// is external and its response size is not a contract: a client timeout bounds
// how long a body may take to arrive but not how large it may grow, so a
// trickled or oversized body would otherwise be an unbounded allocation.
const maxResponseBytes = 1 << 20

// exchangeResponse merges the success fields and the failure fields, because
// the provider returns both shapes under HTTP 200 and only the presence of a
// non-zero errcode distinguishes them.
type exchangeResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	OpenID      string `json:"openid"`
	UnionID     string `json:"unionid"`
	Scope       string `json:"scope"`
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
}

// Verify exchanges code for a verified identity.
func (v *verifier) Verify(ctx context.Context, code string) (*VerifiedIdentity, error) {
	// An empty code cannot succeed. Refusing it here keeps the secret off the
	// wire and spares the shared rate limit a request whose outcome is
	// already known, matching the closed posture NewVerifier takes towards
	// missing credentials.
	if code == "" {
		return nil, fmt.Errorf("%w: authorization code is empty", ErrInvalidCredential)
	}

	query := url.Values{}
	query.Set("appid", v.appID)
	query.Set("secret", v.appSecret)
	query.Set("code", code)
	query.Set("grant_type", "authorization_code")

	requestURL := v.endpoint + "?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		// No exchange took place, so this is a configuration fault rather
		// than anything the provider said. The URL carries the secret, so the
		// construction error's own text cannot be surfaced verbatim.
		return nil, fmt.Errorf("%w: cannot build exchange request: %s",
			ErrUnavailable, v.redact(err.Error()))
	}

	resp, err := v.client.Do(req)
	if err != nil {
		// A context failure is reported before anything else, because its
		// sentinel is what lets a caller tell its own abort apart from an
		// upstream fault. These errors carry no URL, so they are the one
		// transport failure that can be wrapped rather than flattened.
		switch {
		case errors.Is(err, context.Canceled):
			// The caller withdrew the request. Retrying is not merely
			// unhelpful here, it contradicts the instruction.
			return nil, fmt.Errorf("%w: exchange aborted by caller", context.Canceled)
		case errors.Is(err, context.DeadlineExceeded):
			return nil, fmt.Errorf("%w: %w", ErrRetryable, context.DeadlineExceeded)
		}

		// Any other transport failure returns a *url.Error whose message
		// embeds the full request URL — secret included. It is redacted and
		// flattened into text here rather than wrapped, so no path can reach
		// the original message.
		return nil, fmt.Errorf("%w: exchange request failed: %s",
			ErrRetryable, v.redact(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusInternalServerError ||
		resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusRequestTimeout {
		// A gateway-level rate limit or timeout is the same transient
		// condition the vendor expresses as errcode 45011 and -1, and is
		// classified the same way.
		return nil, fmt.Errorf("%w: provider returned status %d", ErrRetryable, resp.StatusCode)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: provider returned status %d", ErrMalformedResponse, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read exchange response: %s",
			ErrRetryable, v.redact(err.Error()))
	}

	// The provider serves this payload as text/plain, so the content type is
	// deliberately not consulted.
	var parsed exchangeResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		// Redaction runs before truncation, never after: cutting first can
		// split the secret, and a fragment no longer matches the text being
		// searched for, so the surviving prefix would escape untouched.
		return nil, fmt.Errorf("%w: cannot decode exchange response: %s",
			ErrMalformedResponse, truncate(v.redact(string(body)), maxErrorBodyBytes))
	}

	if parsed.ErrCode != 0 {
		return nil, &VendorError{
			Code:     parsed.ErrCode,
			Msg:      v.redact(parsed.ErrMsg),
			category: classifyVendorCode(parsed.ErrCode),
		}
	}

	// A successful exchange always carries the per-application identifier.
	// Its absence is refused even when the cross-application identifier is
	// present: a response missing a field the provider always sends is a
	// response whose shape is not understood, and an identity is not issued
	// from one.
	if parsed.OpenID == "" {
		return nil, fmt.Errorf("%w: exchange succeeded without an identifier", ErrMalformedResponse)
	}

	identity := &VerifiedIdentity{
		UnionID: parsed.UnionID,
		OpenID:  parsed.OpenID,
		Scope:   parsed.Scope,
	}
	if parsed.UnionID != "" {
		identity.Subject = parsed.UnionID
		identity.SubjectSource = SubjectFromUnionID
	} else {
		identity.Subject = parsed.OpenID
		identity.SubjectSource = SubjectFromOpenID
	}

	return identity, nil
}

// redact removes this verifier's secret from text bound for a caller.
func (v *verifier) redact(s string) string {
	return redactSecret(s, v.appSecret)
}

// truncate caps s at n bytes, marking the cut so a reader can tell the text is
// incomplete. The cut is pulled back to a rune boundary, because a body that
// carries non-ASCII text would otherwise leave a partial sequence in an error
// destined for a log or a JSON payload.
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
