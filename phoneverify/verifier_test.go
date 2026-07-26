// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package phoneverify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Fixed response payloads. They are held in source so the suite carries no
// network dependency of any kind and runs offline.
const (
	fixtureSuccess = `{"Code":"OK","Message":"OK","RequestId":"REQ-SUCCESS",` +
		`"GetMobileResultDTO":{"Mobile":"13800001111"}}`

	fixtureSuccessWithoutMobile = `{"Code":"OK","Message":"OK","RequestId":"REQ-NO-MOBILE",` +
		`"GetMobileResultDTO":{"Mobile":""}}`

	fixtureTokenInvalid = `{"Code":"isv.TOKEN_INVALID","Message":"token is invalid",` +
		`"RequestId":"REQ-TOKEN-INVALID"}`

	fixtureTokenExpired = `{"Code":"InvalidBizToken.Expired","Message":"token has expired",` +
		`"RequestId":"REQ-TOKEN-EXPIRED"}`

	fixtureTokenUsedElsewhere = `{"Code":"isv.TOKEN_UNAUTHORIZED_USED",` +
		`"Message":"token issued for another operation","RequestId":"REQ-TOKEN-CROSSED"}`

	fixtureRetrievalFailed = `{"Code":"GET_MOBILE_FAILED","Message":"retrieval failed",` +
		`"RequestId":"REQ-RETRIEVAL-FAILED"}`

	fixturePermissionDenied = `{"Code":"isv.RAM_PERMISSION_DENY","Message":"no permission",` +
		`"RequestId":"REQ-PERMISSION"}`

	fixtureProductUnsubscribed = `{"Code":"isv.PRODUCT_UNSUBSCRIBE","Message":"not subscribed",` +
		`"RequestId":"REQ-UNSUBSCRIBED"}`

	fixtureSchemeNotFound = `{"Code":"isv.VERIFY_SCHEME_NOT_EXIST","Message":"scheme not found",` +
		`"RequestId":"REQ-SCHEME"}`

	fixtureSignatureMismatch = `{"Code":"SignatureDoesNotMatch","Message":"signature mismatch",` +
		`"RequestId":"REQ-SIGNATURE"}`

	fixtureRateLimited = `{"Code":"isp.QPS_LIMIT","Message":"too many requests",` +
		`"RequestId":"REQ-QPS"}`

	fixtureBusinessLimited = `{"Code":"isv.BUSINESS_LIMIT_CONTROL","Message":"limited",` +
		`"RequestId":"REQ-BUSINESS-LIMIT"}`

	fixtureSystemError = `{"Code":"isp.SYSTEM_ERROR","Message":"system error",` +
		`"RequestId":"REQ-SYSTEM"}`

	fixtureUnknownCode = `{"Code":"NOT_A_DOCUMENTED_CODE","Message":"who knows",` +
		`"RequestId":"REQ-UNKNOWN"}`

	fixtureMalformedBody = `this is not a JSON document at all`
)

const (
	testAppKey = "test-app-key"
	testKeyID  = "test-access-key-id"

	// The secret deliberately contains characters the query encoder escapes.
	// A secret made only of unreserved characters would appear in a transport
	// error unchanged, and a redaction step that matches only the configured
	// form would pass such a test while leaking every realistic secret.
	testSecret = "ab+cd/ef=gh&ij kl"

	testToken = "test-authentication-token"
)

// recorder captures what the stub server received. The handler runs on the
// server's own goroutine while assertions run on the test's, so every field is
// guarded.
type recorder struct {
	mu      sync.Mutex
	query   url.Values
	method  string
	path    string
	rawURL  string
	callNum int
}

func (r *recorder) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.query = req.URL.Query()
	r.method = req.Method
	r.path = req.URL.Path
	r.rawURL = req.URL.String()
	r.callNum++
}

func (r *recorder) snapshot() (query url.Values, method, path, rawURL string, calls int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.query, r.method, r.path, r.rawURL, r.callNum
}

// newStubServer serves one fixed response and records every request.
func newStubServer(t *testing.T, status int, body string) (*httptest.Server, *recorder) {
	t.Helper()

	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// testConfig is a complete configuration pointed at endpoint.
func testConfig(endpoint string) PhoneAuthConfig {
	return PhoneAuthConfig{
		AppKey:          testAppKey,
		AccessKeyID:     testKeyID,
		AccessKeySecret: testSecret,
		Endpoint:        endpoint,
		Timeout:         5 * time.Second,
	}
}

func TestVerifyExchangeOutcomes(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		status         int
		body           string
		wantCategory   error
		wantVendorCode string
		wantRequestID  string
		wantMobile     string
	}{
		"verified phone number is returned": {
			status:        http.StatusOK,
			body:          fixtureSuccess,
			wantMobile:    "13800001111",
			wantRequestID: "REQ-SUCCESS",
		},
		"invalid token is refused": {
			status:         http.StatusOK,
			body:           fixtureTokenInvalid,
			wantCategory:   ErrInvalidCredential,
			wantVendorCode: "isv.TOKEN_INVALID",
			wantRequestID:  "REQ-TOKEN-INVALID",
		},
		"expired token is refused": {
			status:         http.StatusOK,
			body:           fixtureTokenExpired,
			wantCategory:   ErrInvalidCredential,
			wantVendorCode: "InvalidBizToken.Expired",
			wantRequestID:  "REQ-TOKEN-EXPIRED",
		},
		"token issued for another operation is refused": {
			status:         http.StatusOK,
			body:           fixtureTokenUsedElsewhere,
			wantCategory:   ErrInvalidCredential,
			wantVendorCode: "isv.TOKEN_UNAUTHORIZED_USED",
			wantRequestID:  "REQ-TOKEN-CROSSED",
		},
		"failed retrieval is refused": {
			status:         http.StatusOK,
			body:           fixtureRetrievalFailed,
			wantCategory:   ErrInvalidCredential,
			wantVendorCode: "GET_MOBILE_FAILED",
			wantRequestID:  "REQ-RETRIEVAL-FAILED",
		},
		"missing permission reports unavailable rather than a rejected user": {
			status:         http.StatusOK,
			body:           fixturePermissionDenied,
			wantCategory:   ErrUnavailable,
			wantVendorCode: "isv.RAM_PERMISSION_DENY",
			wantRequestID:  "REQ-PERMISSION",
		},
		"unsubscribed product reports unavailable": {
			status:         http.StatusOK,
			body:           fixtureProductUnsubscribed,
			wantCategory:   ErrUnavailable,
			wantVendorCode: "isv.PRODUCT_UNSUBSCRIBE",
			wantRequestID:  "REQ-UNSUBSCRIBED",
		},
		"absent verification scheme reports unavailable": {
			status:         http.StatusOK,
			body:           fixtureSchemeNotFound,
			wantCategory:   ErrUnavailable,
			wantVendorCode: "isv.VERIFY_SCHEME_NOT_EXIST",
			wantRequestID:  "REQ-SCHEME",
		},
		"signature mismatch reports unavailable": {
			status:         http.StatusOK,
			body:           fixtureSignatureMismatch,
			wantCategory:   ErrUnavailable,
			wantVendorCode: "SignatureDoesNotMatch",
			wantRequestID:  "REQ-SIGNATURE",
		},
		"rate limit is retryable": {
			status:         http.StatusOK,
			body:           fixtureRateLimited,
			wantCategory:   ErrRetryable,
			wantVendorCode: "isp.QPS_LIMIT",
			wantRequestID:  "REQ-QPS",
		},
		"provider side limit is retryable": {
			status:         http.StatusOK,
			body:           fixtureBusinessLimited,
			wantCategory:   ErrRetryable,
			wantVendorCode: "isv.BUSINESS_LIMIT_CONTROL",
			wantRequestID:  "REQ-BUSINESS-LIMIT",
		},
		"provider system error is retryable": {
			status:         http.StatusOK,
			body:           fixtureSystemError,
			wantCategory:   ErrRetryable,
			wantVendorCode: "isp.SYSTEM_ERROR",
			wantRequestID:  "REQ-SYSTEM",
		},
		"unrecognised code fails closed": {
			status:         http.StatusOK,
			body:           fixtureUnknownCode,
			wantCategory:   ErrInvalidCredential,
			wantVendorCode: "NOT_A_DOCUMENTED_CODE",
			wantRequestID:  "REQ-UNKNOWN",
		},
		"success without a phone number is malformed": {
			status:       http.StatusOK,
			body:         fixtureSuccessWithoutMobile,
			wantCategory: ErrMalformedResponse,
		},
		"undecodable body is malformed": {
			status:       http.StatusOK,
			body:         fixtureMalformedBody,
			wantCategory: ErrMalformedResponse,
		},
		"rejected token under a failure status is refused": {
			status:         http.StatusBadRequest,
			body:           fixtureTokenInvalid,
			wantCategory:   ErrInvalidCredential,
			wantVendorCode: "isv.TOKEN_INVALID",
			wantRequestID:  "REQ-TOKEN-INVALID",
		},
		"missing permission under a failure status reports unavailable": {
			status:         http.StatusForbidden,
			body:           fixturePermissionDenied,
			wantCategory:   ErrUnavailable,
			wantVendorCode: "isv.RAM_PERMISSION_DENY",
			wantRequestID:  "REQ-PERMISSION",
		},
		"rate limit under a failure status is retryable": {
			status:         http.StatusTooManyRequests,
			body:           fixtureRateLimited,
			wantCategory:   ErrRetryable,
			wantVendorCode: "isp.QPS_LIMIT",
			wantRequestID:  "REQ-QPS",
		},
		"unrecognised code under a server fault falls back to the status": {
			status:         http.StatusInternalServerError,
			body:           fixtureUnknownCode,
			wantCategory:   ErrRetryable,
			wantVendorCode: "NOT_A_DOCUMENTED_CODE",
			wantRequestID:  "REQ-UNKNOWN",
		},
		"unrecognised code under a client fault fails closed": {
			status:         http.StatusBadRequest,
			body:           fixtureUnknownCode,
			wantCategory:   ErrInvalidCredential,
			wantVendorCode: "NOT_A_DOCUMENTED_CODE",
			wantRequestID:  "REQ-UNKNOWN",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv, _ := newStubServer(t, tc.status, tc.body)
			verifier, err := NewVerifier(testConfig(srv.URL))
			require.NoError(t, err)

			phone, err := verifier.Verify(context.Background(), testToken)

			if tc.wantCategory == nil {
				require.NoError(t, err)
				require.NotNil(t, phone)
				require.Equal(t, tc.wantMobile, phone.Mobile)
				require.Equal(t, tc.wantRequestID, phone.RequestID)
				return
			}

			require.Error(t, err)
			require.Nil(t, phone)
			require.ErrorIs(t, err, tc.wantCategory)
			require.NotContains(t, err.Error(), testSecret,
				"the secret must not reach a caller through an error")

			if tc.wantVendorCode != "" {
				var vendorErr *VendorError
				require.ErrorAs(t, err, &vendorErr)
				require.Equal(t, tc.wantVendorCode, vendorErr.Code)
				require.Equal(t, tc.wantRequestID, vendorErr.RequestID)
				require.Equal(t, tc.status, vendorErr.HTTPStatus)
				require.ErrorIs(t, vendorErr, tc.wantCategory,
					"the vendor detail and the category must hold on the same value")
			}
		})
	}
}

func TestVerifySendsTheExpectedRequest(t *testing.T) {
	t.Parallel()

	srv, rec := newStubServer(t, http.StatusOK, fixtureSuccess)
	verifier, err := NewVerifier(testConfig(srv.URL))
	require.NoError(t, err)

	_, err = verifier.Verify(context.Background(), testToken)
	require.NoError(t, err)

	query, _, _, rawURL, calls := rec.snapshot()
	require.Equal(t, 1, calls, "one exchange means one request")
	require.Equal(t, "GetMobile", query.Get("Action"))
	require.Equal(t, "2017-05-25", query.Get("Version"))
	require.Equal(t, testToken, query.Get("AccessToken"))
	require.Empty(t, query.Get("AppKey"),
		"the application key addresses the mobile side and has no place in this exchange")
	require.NotContains(t, rawURL, testSecret,
		"the signing key must never travel with the request")
	require.NotContains(t, rawURL, url.QueryEscape(testSecret),
		"the signing key must never travel with the request, encoded either")
	require.NotEmpty(t, query.Get("Signature"), "the request is expected to be signed")
}

func TestVerifyTreatsTransportFailureAsRetryable(t *testing.T) {
	t.Parallel()

	srv, _ := newStubServer(t, http.StatusOK, fixtureSuccess)
	verifier, err := NewVerifier(testConfig(srv.URL))
	require.NoError(t, err)

	// Closing the server first makes the exchange fail at the transport,
	// which is the path whose error text embeds the full request URL.
	srv.Close()

	phone, err := verifier.Verify(context.Background(), testToken)
	require.Error(t, err)
	require.Nil(t, phone)
	require.ErrorIs(t, err, ErrRetryable)
	require.NotContains(t, err.Error(), testSecret)
	require.NotContains(t, err.Error(), url.QueryEscape(testSecret))
	require.NotContains(t, err.Error(), testKeyID,
		"the key id travels with the signed request and must be redacted too")
}

func TestVerifyRefusesAnEmptyToken(t *testing.T) {
	t.Parallel()

	srv, rec := newStubServer(t, http.StatusOK, fixtureSuccess)
	verifier, err := NewVerifier(testConfig(srv.URL))
	require.NoError(t, err)

	phone, err := verifier.Verify(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, phone)
	require.ErrorIs(t, err, ErrInvalidCredential)

	_, _, _, _, calls := rec.snapshot()
	require.Zero(t, calls, "an outcome already known must not cost a request")
}

func TestVerifyPreservesContextCancellation(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fixtureSuccess)
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	verifier, err := NewVerifier(testConfig(srv.URL))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// The stub holds the request open until the test releases it, so the
		// exchange is guaranteed to still be in flight when this fires.
		cancel()
	}()

	phone, err := verifier.Verify(ctx, testToken)
	require.Error(t, err)
	require.Nil(t, phone)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, ErrRetryable,
		"a withdrawn request must not be advertised as worth retrying")
	require.NotContains(t, err.Error(), testSecret)
}

func TestVerifyReportsDeadlineAsRetryable(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fixtureSuccess)
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	verifier, err := NewVerifier(testConfig(srv.URL))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	t.Cleanup(cancel)

	phone, err := verifier.Verify(ctx, testToken)
	require.Error(t, err)
	require.Nil(t, phone)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, ErrRetryable,
		"a deadline may well be met on a second attempt")
	require.NotContains(t, err.Error(), testSecret)
}

func TestVerifyIsSafeUnderConcurrentUse(t *testing.T) {
	t.Parallel()

	srv, rec := newStubServer(t, http.StatusOK, fixtureSuccess)
	verifier, err := NewVerifier(testConfig(srv.URL))
	require.NoError(t, err)

	const callers = 8
	var wg sync.WaitGroup
	results := make([]error, callers)
	phones := make([]*VerifiedPhone, callers)

	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			phones[i], results[i] = verifier.Verify(context.Background(), testToken)
		}()
	}
	wg.Wait()

	for i := range callers {
		require.NoError(t, results[i])
		require.NotNil(t, phones[i])
		require.Equal(t, "13800001111", phones[i].Mobile)
	}

	_, _, _, _, calls := rec.snapshot()
	require.Equal(t, callers, calls, "every caller must have reached the provider")
}

func TestNewVerifierRefusesIncompleteCredentials(t *testing.T) {
	t.Parallel()

	cases := map[string]PhoneAuthConfig{
		"no application key": {
			AccessKeyID:     testKeyID,
			AccessKeySecret: testSecret,
		},
		"no access key id": {
			AppKey:          testAppKey,
			AccessKeySecret: testSecret,
		},
		"no access key secret": {
			AppKey:      testAppKey,
			AccessKeyID: testKeyID,
		},
		"nothing configured at all": {},
	}

	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			verifier, err := NewVerifier(cfg)
			require.Error(t, err)
			require.Nil(t, verifier)
			require.ErrorIs(t, err, ErrUnavailable,
				"a capability that cannot serve must say so at assembly time")
			require.NotContains(t, err.Error(), testSecret)
			require.NotContains(t, err.Error(), url.QueryEscape(testSecret))
		})
	}
}

func TestNewVerifierRefusesAnUnusableEndpoint(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"unsupported scheme":     "ftp://dypnsapi.example.com",
		"no scheme":              "dypnsapi.example.com",
		"no host":                "https://",
		"carries a query string": "https://dypnsapi.example.com?Action=GetMobile",
		"not a URL at all":       "https://exa mple.com/\x7f",
	}

	for name, endpoint := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := testConfig(endpoint)
			verifier, err := NewVerifier(cfg)
			require.Error(t, err)
			require.Nil(t, verifier)
			require.ErrorIs(t, err, ErrUnavailable)
			require.NotContains(t, err.Error(), testSecret)
		})
	}
}

func TestNewVerifierNormalisesOptionalSettings(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		cfg         PhoneAuthConfig
		wantScheme  string
		wantHost    string
		wantRegion  string
		wantTimeout time.Duration
	}{
		"empty optional settings take their defaults": {
			cfg: PhoneAuthConfig{
				AppKey:          testAppKey,
				AccessKeyID:     testKeyID,
				AccessKeySecret: testSecret,
			},
			wantScheme:  "https",
			wantHost:    "dypnsapi.aliyuncs.com",
			wantRegion:  DefaultRegionID,
			wantTimeout: defaultTimeout,
		},
		"a negative timeout falls back to the default": {
			cfg: PhoneAuthConfig{
				AppKey:          testAppKey,
				AccessKeyID:     testKeyID,
				AccessKeySecret: testSecret,
				Timeout:         -time.Second,
			},
			wantScheme:  "https",
			wantHost:    "dypnsapi.aliyuncs.com",
			wantRegion:  DefaultRegionID,
			wantTimeout: defaultTimeout,
		},
		"a local endpoint keeps its scheme and port": {
			cfg: PhoneAuthConfig{
				AppKey:          testAppKey,
				AccessKeyID:     testKeyID,
				AccessKeySecret: testSecret,
				RegionID:        "cn-shanghai",
				Endpoint:        "http://127.0.0.1:45678",
				Timeout:         3 * time.Second,
			},
			wantScheme:  "http",
			wantHost:    "127.0.0.1:45678",
			wantRegion:  "cn-shanghai",
			wantTimeout: 3 * time.Second,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			built, err := NewVerifier(tc.cfg)
			require.NoError(t, err)

			v, ok := built.(*verifier)
			require.True(t, ok, "want the package's own verifier type")
			require.Equal(t, tc.wantScheme, v.scheme)
			require.Equal(t, tc.wantHost, v.host)
			require.Equal(t, tc.wantRegion, v.regionID)
			require.Equal(t, tc.wantTimeout, v.timeout)
		})
	}
}

func TestRenderingNeverRevealsTheSecret(t *testing.T) {
	t.Parallel()

	cfg := testConfig("https://dypnsapi.example.com")

	built, err := NewVerifier(cfg)
	require.NoError(t, err)

	encoded, err := json.Marshal(cfg)
	require.NoError(t, err)

	nested, err := json.Marshal(struct {
		Phone PhoneAuthConfig `json:"phone"`
	}{Phone: cfg})
	require.NoError(t, err)

	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info("configuration", slog.Any("phone", cfg))

	renderings := map[string]string{
		"value with the default verb":   fmt.Sprintf("%v", cfg),
		"value with the plus verb":      fmt.Sprintf("%+v", cfg),
		"pointer with the default verb": fmt.Sprintf("%v", &cfg),
		"inside a slice":                fmt.Sprintf("%v", []PhoneAuthConfig{cfg}),
		"inside a struct":               fmt.Sprintf("%+v", struct{ Phone PhoneAuthConfig }{cfg}),
		"encoded as JSON":               string(encoded),
		"encoded as nested JSON":        string(nested),
		"emitted by a structured log":   logged.String(),
		"the verifier itself":           fmt.Sprintf("%v", built),
	}

	for name, rendered := range renderings {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.NotContains(t, rendered, testSecret)
			require.NotContains(t, rendered, url.QueryEscape(testSecret))
			require.Contains(t, rendered, redactionPlaceholder,
				"the secret's presence should still be visible")
		})
	}
}

func TestRedactSecrets(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		text    string
		secrets []string
		want    string
	}{
		"plain occurrence is removed": {
			text:    "signing with " + testSecret + " failed",
			secrets: []string{testSecret},
			want:    "signing with " + redactionPlaceholder + " failed",
		},
		"query encoded occurrence is removed": {
			text:    "GET /?Signature=" + url.QueryEscape(testSecret),
			secrets: []string{testSecret},
			want:    "GET /?Signature=" + redactionPlaceholder,
		},
		"every listed secret is removed": {
			text:    "id=" + testKeyID + "&key=" + testSecret,
			secrets: []string{testSecret, testKeyID},
			want:    "id=" + redactionPlaceholder + "&key=" + redactionPlaceholder,
		},
		"an empty secret redacts nothing": {
			text:    "nothing to hide",
			secrets: []string{""},
			want:    "nothing to hide",
		},
		"text without an occurrence is untouched": {
			text:    "plain text",
			secrets: []string{testSecret},
			want:    "plain text",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, redactSecrets(tc.text, tc.secrets...))
		})
	}
}

func TestRedactionRunsBeforeTruncation(t *testing.T) {
	t.Parallel()

	// The secret sits astride the cut: truncating first would leave an
	// unmatched prefix of it in the surviving text. The placeholder that
	// replaces it lands astride the cut too, so only its own leading part
	// survives — which is exactly the evidence that redaction ran first.
	straddling := strings.Repeat("x", maxErrorTextBytes-len(testSecret)/2) +
		testSecret + strings.Repeat("y", 100)

	got := truncate(redactSecrets(straddling, testSecret), maxErrorTextBytes)

	require.NotContains(t, got, testSecret)
	require.NotContains(t, got, testSecret[:len(testSecret)/2],
		"not even a leading fragment of the secret may survive the cut")
	require.Contains(t, got, "[REDACT",
		"the replacement must already have happened when the cut was made")
	require.True(t, strings.HasSuffix(got, "..."), "a cut text should say so")
	require.LessOrEqual(t, len(got), maxErrorTextBytes+len("..."))

	// The same text with the secret clear of the cut keeps the whole
	// placeholder, so the assertion above is not merely reading a coincidence.
	wellBefore := "signed with " + testSecret + strings.Repeat("y", 400)

	got = truncate(redactSecrets(wellBefore, testSecret), maxErrorTextBytes)

	require.NotContains(t, got, testSecret)
	require.Contains(t, got, redactionPlaceholder)
}

func TestTruncateKeepsRuneBoundaries(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		text  string
		limit int
		want  string
	}{
		"text within the limit is untouched": {
			text:  "short",
			limit: 16,
			want:  "short",
		},
		"text at the limit is untouched": {
			text:  "exactly",
			limit: 7,
			want:  "exactly",
		},
		"a multi byte rune is not split": {
			// Each character below is three bytes; a four-byte cut would
			// land inside the second one.
			text:  "错误信息",
			limit: 4,
			want:  "错...",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, truncate(tc.text, tc.limit))
		})
	}
}

func TestClassifyVendorCode(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		code string
		want error
	}{
		"invalid token":                {code: codeTokenInvalid, want: ErrInvalidCredential},
		"token used elsewhere":         {code: codeTokenUnauthorizedUsed, want: ErrInvalidCredential},
		"expired token":                {code: codeTokenExpired, want: ErrInvalidCredential},
		"token check failure":          {code: codeTokenCheckFailed, want: ErrInvalidCredential},
		"failed retrieval":             {code: codeRetrievalFailed, want: ErrInvalidCredential},
		"denied permission":            {code: codePermissionDenied, want: ErrUnavailable},
		"forbidden operation":          {code: codeForbiddenAction, want: ErrUnavailable},
		"unsubscribed product":         {code: codeProductUnsubscribed, want: ErrUnavailable},
		"absent scheme":                {code: codeSchemeNotFound, want: ErrUnavailable},
		"mismatched signature":         {code: codeSignatureMismatch, want: ErrUnavailable},
		"incomplete signature":         {code: codeSignatureIncomplete, want: ErrUnavailable},
		"rate limit":                   {code: codeRateLimited, want: ErrRetryable},
		"provider side limit":          {code: codeBusinessLimited, want: ErrRetryable},
		"provider system error":        {code: codeSystemError, want: ErrRetryable},
		"provider unknown error":       {code: codeUnknownError, want: ErrRetryable},
		"unrecognised code":            {code: "NO_SUCH_CODE", want: ErrInvalidCredential},
		"empty code":                   {code: "", want: ErrInvalidCredential},
		"shared prefix is not grouped": {code: "isv.SOMETHING_ELSE", want: ErrInvalidCredential},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.True(t, errors.Is(classifyVendorCode(tc.code), tc.want))
		})
	}
}

func TestClassifyHTTPStatus(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		status int
		want   error
	}{
		"server fault is retryable":     {status: http.StatusInternalServerError, want: ErrRetryable},
		"gateway fault is retryable":    {status: http.StatusBadGateway, want: ErrRetryable},
		"rate limit is retryable":       {status: http.StatusTooManyRequests, want: ErrRetryable},
		"request timeout is retryable":  {status: http.StatusRequestTimeout, want: ErrRetryable},
		"bad request fails closed":      {status: http.StatusBadRequest, want: ErrInvalidCredential},
		"forbidden fails closed":        {status: http.StatusForbidden, want: ErrInvalidCredential},
		"an absent status fails closed": {status: 0, want: ErrInvalidCredential},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.True(t, errors.Is(classifyHTTPStatus(tc.status), tc.want))
		})
	}
}
