// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wechatverify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testAppID  = "wxappid-under-test"
	testSecret = "s3cr3t-value-that-must-never-surface"
	testCode   = "code-under-test"

	exchangePath = "/sns/oauth2/access_token"
)

// Response payloads reproduced from the provider's documented shapes. They are
// held in source so the suite needs no network and no external file.
const (
	fixtureSuccessWithUnionID = `{"access_token":"AT","expires_in":7200,` +
		`"refresh_token":"RT","openid":"OPENID-1","scope":"snsapi_userinfo","unionid":"UNIONID-1"}`

	fixtureSuccessOpenIDOnly = `{"access_token":"AT","expires_in":7200,` +
		`"refresh_token":"RT","openid":"OPENID-2","scope":"snsapi_userinfo"}`

	fixtureSuccessNoIdentifier = `{"access_token":"AT","expires_in":7200,"scope":"snsapi_userinfo"}`

	fixtureCodeAlreadyUsed = `{"errcode":40163,"errmsg":"code been used, hints: [ req_id: xyz ]"}`
	fixtureCodeExpired     = `{"errcode":40029,"errmsg":"invalid code, hints: [ code expired ]"}`
	fixtureCodeInvalid     = `{"errcode":40029,"errmsg":"invalid code"}`
	fixtureSecretMismatch  = `{"errcode":40125,"errmsg":"invalid appsecret"}`
	fixtureCredsMismatch   = `{"errcode":40001,"errmsg":"invalid credential"}`
	fixtureSystemBusy      = `{"errcode":-1,"errmsg":"system error"}`
	fixtureRateLimited     = `{"errcode":45011,"errmsg":"api freq out of limit"}`
	fixtureUnknownCode     = `{"errcode":99999,"errmsg":"something new"}`

	fixtureMalformedBody = `<html><body>gateway says no</body></html>`
)

// recordedRequest captures what the stub actually received, so the request
// shape can be asserted rather than assumed.
type recordedRequest struct {
	path  string
	query url.Values
}

func newStubServer(t *testing.T, status int, body string) (*httptest.Server, *recordedRequest) {
	t.Helper()

	rec := &recordedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.path = r.URL.Path
		rec.query = r.URL.Query()
		// The provider serves JSON under a text/plain content type; the stub
		// reproduces that so a content-type dependency would be caught here.
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	return srv, rec
}

func newTestVerifier(t *testing.T, endpoint string) Verifier {
	t.Helper()

	v, err := NewVerifier(Config{
		AppID:     testAppID,
		AppSecret: testSecret,
		Endpoint:  endpoint,
	})
	if err != nil {
		t.Fatalf("NewVerifier returned an unexpected error: %v", err)
	}
	return v
}

func TestVerifyExchangeOutcomes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		status          int
		body            string
		wantErr         error
		wantVendorCode  int
		wantSubject     string
		wantSource      SubjectSource
		wantUnionID     string
		wantOpenID      string
		wantScope       string
		wantVendorError bool
	}{
		"cross application identifier present": {
			status:      http.StatusOK,
			body:        fixtureSuccessWithUnionID,
			wantSubject: "UNIONID-1",
			wantSource:  SubjectFromUnionID,
			wantUnionID: "UNIONID-1",
			wantOpenID:  "OPENID-1",
			wantScope:   "snsapi_userinfo",
		},
		"per application identifier only is a degraded success": {
			status:      http.StatusOK,
			body:        fixtureSuccessOpenIDOnly,
			wantSubject: "OPENID-2",
			wantSource:  SubjectFromOpenID,
			wantUnionID: "",
			wantOpenID:  "OPENID-2",
			wantScope:   "snsapi_userinfo",
		},
		"code already used": {
			status:          http.StatusOK,
			body:            fixtureCodeAlreadyUsed,
			wantErr:         ErrInvalidCredential,
			wantVendorCode:  40163,
			wantVendorError: true,
		},
		"code expired": {
			status:          http.StatusOK,
			body:            fixtureCodeExpired,
			wantErr:         ErrInvalidCredential,
			wantVendorCode:  40029,
			wantVendorError: true,
		},
		"code invalid": {
			status:          http.StatusOK,
			body:            fixtureCodeInvalid,
			wantErr:         ErrInvalidCredential,
			wantVendorCode:  40029,
			wantVendorError: true,
		},
		"application secret does not match": {
			status:          http.StatusOK,
			body:            fixtureSecretMismatch,
			wantErr:         ErrInvalidCredential,
			wantVendorCode:  40125,
			wantVendorError: true,
		},
		"credential pair does not match": {
			status:          http.StatusOK,
			body:            fixtureCredsMismatch,
			wantErr:         ErrInvalidCredential,
			wantVendorCode:  40001,
			wantVendorError: true,
		},
		"provider busy is retryable": {
			status:          http.StatusOK,
			body:            fixtureSystemBusy,
			wantErr:         ErrRetryable,
			wantVendorCode:  -1,
			wantVendorError: true,
		},
		"rate limited is retryable": {
			status:          http.StatusOK,
			body:            fixtureRateLimited,
			wantErr:         ErrRetryable,
			wantVendorCode:  45011,
			wantVendorError: true,
		},
		"unrecognised code fails closed": {
			status:          http.StatusOK,
			body:            fixtureUnknownCode,
			wantErr:         ErrInvalidCredential,
			wantVendorCode:  99999,
			wantVendorError: true,
		},
		"body is not decodable": {
			status:  http.StatusOK,
			body:    fixtureMalformedBody,
			wantErr: ErrMalformedResponse,
		},
		"success without any identifier": {
			status:  http.StatusOK,
			body:    fixtureSuccessNoIdentifier,
			wantErr: ErrMalformedResponse,
		},
		"upstream server error is retryable": {
			status:  http.StatusBadGateway,
			body:    "upstream unavailable",
			wantErr: ErrRetryable,
		},
		"unexpected client status is malformed": {
			status:  http.StatusForbidden,
			body:    "forbidden",
			wantErr: ErrMalformedResponse,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv, rec := newStubServer(t, tc.status, tc.body)
			v := newTestVerifier(t, srv.URL+exchangePath)

			identity, err := v.Verify(context.Background(), testCode)

			// The exchange must always hit the mobile-app endpoint with the
			// full parameter set — this pins the endpoint choice down.
			if rec.path != exchangePath {
				t.Errorf("request path = %q, want %q", rec.path, exchangePath)
			}
			if got := rec.query.Get("appid"); got != testAppID {
				t.Errorf("appid parameter = %q, want %q", got, testAppID)
			}
			if got := rec.query.Get("secret"); got != testSecret {
				t.Errorf("secret parameter = %q, want %q", got, testSecret)
			}
			if got := rec.query.Get("code"); got != testCode {
				t.Errorf("code parameter = %q, want %q", got, testCode)
			}
			if got := rec.query.Get("grant_type"); got != "authorization_code" {
				t.Errorf("grant_type parameter = %q, want %q", got, "authorization_code")
			}

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Verify error = %v, want category %v", err, tc.wantErr)
				}
				if identity != nil {
					t.Errorf("Verify returned an identity alongside an error: %+v", identity)
				}
				if strings.Contains(err.Error(), testSecret) {
					t.Errorf("error text leaked the application secret: %v", err)
				}
				if tc.wantVendorError {
					var ve *VendorError
					if !errors.As(err, &ve) {
						t.Fatalf("Verify error = %v, want a *VendorError", err)
					}
					if ve.Code != tc.wantVendorCode {
						t.Errorf("VendorError.Code = %d, want %d", ve.Code, tc.wantVendorCode)
					}
					if ve.Msg == "" {
						t.Error("VendorError.Msg is empty, want the provider message preserved")
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("Verify returned an unexpected error: %v", err)
			}
			if identity.Subject != tc.wantSubject {
				t.Errorf("Subject = %q, want %q", identity.Subject, tc.wantSubject)
			}
			if identity.SubjectSource != tc.wantSource {
				t.Errorf("SubjectSource = %q, want %q", identity.SubjectSource, tc.wantSource)
			}
			if identity.UnionID != tc.wantUnionID {
				t.Errorf("UnionID = %q, want %q", identity.UnionID, tc.wantUnionID)
			}
			if identity.OpenID != tc.wantOpenID {
				t.Errorf("OpenID = %q, want %q", identity.OpenID, tc.wantOpenID)
			}
			if identity.Scope != tc.wantScope {
				t.Errorf("Scope = %q, want %q", identity.Scope, tc.wantScope)
			}
		})
	}
}

func TestVerifyTransportFailureIsRetryableAndRedacted(t *testing.T) {
	t.Parallel()

	// A server that is shut down before use gives a deterministic transport
	// failure without depending on the outside network.
	srv, _ := newStubServer(t, http.StatusOK, fixtureSuccessWithUnionID)
	endpoint := srv.URL + exchangePath
	srv.Close()

	v := newTestVerifier(t, endpoint)

	identity, err := v.Verify(context.Background(), testCode)
	if identity != nil {
		t.Errorf("Verify returned an identity for a failed transport: %+v", identity)
	}
	if !errors.Is(err, ErrRetryable) {
		t.Fatalf("Verify error = %v, want category %v", err, ErrRetryable)
	}
	// The transport error embeds the request URL, secret included. This is the
	// path most likely to leak, so it is asserted on its own.
	if strings.Contains(err.Error(), testSecret) {
		t.Errorf("transport error leaked the application secret: %v", err)
	}
	if !strings.Contains(err.Error(), redactionPlaceholder) {
		t.Errorf("transport error did not mark the redaction: %v", err)
	}
}

func TestVerifyMalformedBodyIsTruncatedAndRedacted(t *testing.T) {
	t.Parallel()

	// A body that echoes the request URL back is the shape that would smuggle
	// the secret out through an undecodable response.
	echoed := "gateway error for request with secret=" + testSecret + " " +
		strings.Repeat("x", 2*maxErrorBodyBytes)
	srv, _ := newStubServer(t, http.StatusOK, echoed)
	v := newTestVerifier(t, srv.URL+exchangePath)

	_, err := v.Verify(context.Background(), testCode)
	if !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("Verify error = %v, want category %v", err, ErrMalformedResponse)
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Errorf("malformed-response error leaked the application secret: %v", err)
	}
	if len(err.Error()) > 2*maxErrorBodyBytes {
		t.Errorf("malformed-response error is %d bytes, want the body truncated", len(err.Error()))
	}
}

func TestNewVerifierRefusesMissingCredentials(t *testing.T) {
	t.Parallel()

	cases := map[string]Config{
		"no application id":                {AppSecret: testSecret},
		"no application secret":            {AppID: testAppID},
		"neither identifier nor secret":    {},
		"endpoint set but no credentials":  {Endpoint: "https://example.test/exchange"},
		"client set but no credentials":    {HTTPClient: &http.Client{}},
		"timeout set but no credentials":   {Timeout: time.Second},
		"application id set but no secret": {AppID: testAppID, Endpoint: "https://example.test/exchange"},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			v, err := NewVerifier(cfg)
			if v != nil {
				t.Errorf("NewVerifier returned a verifier for an incomplete configuration")
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("NewVerifier error = %v, want category %v", err, ErrUnavailable)
			}
		})
	}
}

func TestNewVerifierAppliesDefaults(t *testing.T) {
	t.Parallel()

	v, err := NewVerifier(Config{AppID: testAppID, AppSecret: testSecret})
	if err != nil {
		t.Fatalf("NewVerifier returned an unexpected error: %v", err)
	}

	impl, ok := v.(*verifier)
	if !ok {
		t.Fatalf("NewVerifier returned %T, want the package's own verifier type", v)
	}
	if impl.endpoint != DefaultEndpoint {
		t.Errorf("endpoint = %q, want %q", impl.endpoint, DefaultEndpoint)
	}
	if impl.client == nil {
		t.Fatal("client is nil, want a bounded client")
	}
	if impl.client.Timeout != defaultTimeout {
		t.Errorf("client timeout = %v, want %v", impl.client.Timeout, defaultTimeout)
	}
}

func TestNewVerifierKeepsSuppliedClient(t *testing.T) {
	t.Parallel()

	supplied := &http.Client{Timeout: 3 * time.Second}
	v, err := NewVerifier(Config{
		AppID:      testAppID,
		AppSecret:  testSecret,
		HTTPClient: supplied,
		Timeout:    time.Minute,
	})
	if err != nil {
		t.Fatalf("NewVerifier returned an unexpected error: %v", err)
	}

	impl := v.(*verifier)
	if impl.client != supplied {
		t.Error("client was replaced, want the supplied client kept")
	}
}

func TestRenderingNeverRevealsTheSecret(t *testing.T) {
	t.Parallel()

	cfg := Config{AppID: testAppID, AppSecret: testSecret, Endpoint: DefaultEndpoint}

	for name, rendered := range map[string]string{
		"config value":    fmt.Sprintf("%v", cfg),
		"config verbose":  fmt.Sprintf("%+v", cfg),
		"config string":   cfg.String(),
		"config pointer":  fmt.Sprintf("%v", &cfg),
		"config in slice": fmt.Sprintf("%v", []Config{cfg}),
	} {
		if strings.Contains(rendered, testSecret) {
			t.Errorf("%s leaked the application secret: %s", name, rendered)
		}
		if !strings.Contains(rendered, redactionPlaceholder) {
			t.Errorf("%s did not mark the redaction: %s", name, rendered)
		}
	}

	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier returned an unexpected error: %v", err)
	}
	for name, rendered := range map[string]string{
		"verifier value":   fmt.Sprintf("%v", v),
		"verifier verbose": fmt.Sprintf("%+v", v),
	} {
		if strings.Contains(rendered, testSecret) {
			t.Errorf("%s leaked the application secret: %s", name, rendered)
		}
		if !strings.Contains(rendered, redactionPlaceholder) {
			t.Errorf("%s did not mark the redaction: %s", name, rendered)
		}
	}
}

func TestRedactSecret(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		in     string
		secret string
		want   string
	}{
		"single occurrence": {
			in:     "https://host/path?secret=" + testSecret,
			secret: testSecret,
			want:   "https://host/path?secret=" + redactionPlaceholder,
		},
		"repeated occurrence": {
			in:     testSecret + " and " + testSecret,
			secret: testSecret,
			want:   redactionPlaceholder + " and " + redactionPlaceholder,
		},
		"empty secret leaves text untouched": {
			in:     "nothing to hide",
			secret: "",
			want:   "nothing to hide",
		},
		"absent secret leaves text untouched": {
			in:     "nothing to hide",
			secret: testSecret,
			want:   "nothing to hide",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := redactSecret(tc.in, tc.secret); got != tc.want {
				t.Errorf("redactSecret() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifyVendorCode(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		code int
		want error
	}{
		"code already used":     {code: codeCodeAlreadyUsed, want: ErrInvalidCredential},
		"code invalid":          {code: codeInvalidCode, want: ErrInvalidCredential},
		"application secret":    {code: codeInvalidAppSecret, want: ErrInvalidCredential},
		"credential pair":       {code: codeInvalidCredsPair, want: ErrInvalidCredential},
		"application id":        {code: codeInvalidAppID, want: ErrInvalidCredential},
		"code missing":          {code: codeMissingCode, want: ErrInvalidCredential},
		"provider busy":         {code: codeSystemBusy, want: ErrRetryable},
		"rate limited":          {code: codeRateLimited, want: ErrRetryable},
		"unrecognised positive": {code: 99999, want: ErrInvalidCredential},
		"unrecognised negative": {code: -42, want: ErrInvalidCredential},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := classifyVendorCode(tc.code); !errors.Is(got, tc.want) {
				t.Errorf("classifyVendorCode(%d) = %v, want %v", tc.code, got, tc.want)
			}
		})
	}
}
