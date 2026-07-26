// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wechatverify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// maxErrorBodyBytes bounds how much of an unparseable body is echoed back in an
// error. The body is provider-controlled text; quoting it wholesale would make
// the error unbounded.
const maxErrorBodyBytes = 256

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
	query := url.Values{}
	query.Set("appid", v.appID)
	query.Set("secret", v.appSecret)
	query.Set("code", code)
	query.Set("grant_type", "authorization_code")

	requestURL := v.endpoint + "?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		// The URL carries the secret, so the construction error's own text
		// cannot be surfaced verbatim.
		return nil, fmt.Errorf("%w: cannot build exchange request: %s",
			ErrMalformedResponse, v.redact(err.Error()))
	}

	resp, err := v.client.Do(req)
	if err != nil {
		// A transport failure returns a *url.Error whose message embeds the
		// full request URL — secret included. It is redacted and flattened
		// into text here rather than wrapped, so no path can reach the
		// original message.
		return nil, fmt.Errorf("%w: exchange request failed: %s",
			ErrRetryable, v.redact(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusInternalServerError {
		return nil, fmt.Errorf("%w: provider returned status %d", ErrRetryable, resp.StatusCode)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("%w: provider returned status %d", ErrMalformedResponse, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read exchange response: %s",
			ErrRetryable, v.redact(err.Error()))
	}

	// The provider serves this payload as text/plain, so the content type is
	// deliberately not consulted.
	var parsed exchangeResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("%w: cannot decode exchange response: %s",
			ErrMalformedResponse, v.redact(truncate(string(body), maxErrorBodyBytes)))
	}

	if parsed.ErrCode != 0 {
		return nil, &VendorError{
			Code:     parsed.ErrCode,
			Msg:      v.redact(parsed.ErrMsg),
			category: classifyVendorCode(parsed.ErrCode),
		}
	}

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
// incomplete.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
