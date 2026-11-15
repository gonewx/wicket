// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/replay"
)

const userInfoTestEndpoint = "https://wicket.test/connect/userinfo"

// userInfoProofKey signs userinfo proofs in these tests.
type userInfoProofKey struct{ private *ecdsa.PrivateKey }

func newUserInfoProofKey(t *testing.T) userInfoProofKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return userInfoProofKey{private: key}
}

func (k userInfoProofKey) members() (string, string) {
	x, y := make([]byte, 32), make([]byte, 32)
	k.private.X.FillBytes(x)
	k.private.Y.FillBytes(y)
	return base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y)
}

// thumbprint is computed here from the canonical JSON (RFC 7638).
func (k userInfoProofKey) thumbprint() string {
	x, y := k.members()
	digest := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// proof signs a GET proof for the userinfo endpoint carrying the ath of
// token.
func (k userInfoProofKey) proof(t *testing.T, token string, jti string, now time.Time) string {
	t.Helper()
	encode := base64.RawURLEncoding.EncodeToString
	x, y := k.members()
	header, _ := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256",
		"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y},
	})
	tokenDigest := sha256.Sum256([]byte(token))
	claims, _ := json.Marshal(map[string]any{
		"jti": jti, "htm": http.MethodGet, "htu": userInfoTestEndpoint, "iat": now.Unix(),
		"ath": encode(tokenDigest[:]),
	})
	input := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + encode(signature)
}

func TestDPoPAuthorizationParsing(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		header    string
		token     string
		found     bool
		malformed bool
	}{
		"DPoP scheme":          {header: "DPoP abc.def", token: "abc.def", found: true},
		"lower case scheme":    {header: "dpop abc", token: "abc", found: true},
		"upper case scheme":    {header: "DPOP abc", token: "abc", found: true},
		"several spaces":       {header: "DPoP   abc", token: "abc", found: true},
		"surrounding spaces":   {header: "  DPoP abc  ", token: "abc", found: true},
		"scheme only":          {header: "DPoP", found: true, malformed: true},
		"scheme and spaces":    {header: "DPoP   ", found: true, malformed: true},
		"token with a space":   {header: "DPoP abc def", found: true, malformed: true},
		"token with a tab":     {header: "DPoP abc\tdef", found: true, malformed: true},
		"bearer scheme":        {header: "Bearer abc"},
		"no header":            {header: ""},
		"scheme prefix only":   {header: "DPoPabc"},
		"tab after the scheme": {header: "DPoP\tabc"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, userInfoTestEndpoint, nil)
			if tc.header != "" {
				request.Header.Set("Authorization", tc.header)
			}
			token, found, malformed := dpopAuthorization(request)
			if token != tc.token || found != tc.found || malformed != tc.malformed {
				t.Fatalf("= %q %v %v, want %q %v %v", token, found, malformed, tc.token, tc.found, tc.malformed)
			}
		})
	}
}

func newDPoPUserInfoHandler(t *testing.T, cnf any, registry replay.Registry, now time.Time, logger *slog.Logger) *UserInfoHandler {
	t.Helper()
	handler := newUserInfoHandlerUnderTest(userInfoResultWith(cnf), map[string]any{"sub": "subject-1"})
	if logger != nil {
		handler.logger = logger
	}
	options := dpop.Options{SigningAlgorithms: []string{"ES256"}}
	handler.SetDPoP(dpop.NewVerifier(options), registry, options, fixedClock{now: now})
	return handler
}

func TestUserInfoDPoPAcceptsABoundToken(t *testing.T) {
	t.Parallel()
	const token = "bound-token"
	now := time.Unix(1_800_000_000, 0)
	key := newUserInfoProofKey(t)
	handler := newDPoPUserInfoHandler(t, map[string]any{"jkt": key.thumbprint()}, replay.NewMemoryRegistry(), now, nil)

	proof := key.proof(t, token, "jti-1", now)
	for attempt, wantStatus := range []int{http.StatusOK, http.StatusUnauthorized} {
		request := httptest.NewRequest(http.MethodGet, userInfoTestEndpoint, nil)
		request.Header.Set("Authorization", "DPoP "+token)
		request.Header.Set(wicket.DPoPHeaderName, proof)
		recorder := httptest.NewRecorder()
		if err := handler.Process(recorder, request); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if recorder.Code != wantStatus {
			t.Fatalf("attempt %d: status = %d, want %d", attempt, recorder.Code, wantStatus)
		}
		if wantStatus != http.StatusOK {
			if got := recorder.Header().Get("WWW-Authenticate"); got != `DPoP error="invalid_dpop_proof", algs="ES256"` {
				t.Fatalf("replay challenge = %q", got)
			}
		}
	}
}

func TestUserInfoDPoPRejectsMalformedRequests(t *testing.T) {
	t.Parallel()
	const token = "bound-token"
	now := time.Unix(1_800_000_000, 0)
	key := newUserInfoProofKey(t)
	cases := map[string]struct {
		method        string
		authorization string
		form          string
	}{
		"scheme without a token":  {method: http.MethodGet, authorization: "DPoP"},
		"token with whitespace":   {method: http.MethodGet, authorization: "DPoP bound token"},
		"token also in the form":  {method: http.MethodPost, authorization: "DPoP " + token, form: "access_token=" + token},
		"empty token in the form": {method: http.MethodPost, authorization: "DPoP " + token, form: "access_token="},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			registry := &recordingRegistry{}
			handler := newDPoPUserInfoHandler(t, map[string]any{"jkt": key.thumbprint()}, registry, now, nil)
			var body *strings.Reader
			if tc.form != "" {
				body = strings.NewReader(tc.form)
			} else {
				body = strings.NewReader("")
			}
			request := httptest.NewRequest(tc.method, userInfoTestEndpoint, body)
			if tc.form != "" {
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			request.Header.Set("Authorization", tc.authorization)
			request.Header.Set(wicket.DPoPHeaderName, key.proof(t, token, "jti-"+name, now))
			recorder := httptest.NewRecorder()
			if err := handler.Process(recorder, request); err != nil {
				t.Fatalf("Process: %v", err)
			}
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", recorder.Code)
			}
			if got := recorder.Header().Get("WWW-Authenticate"); got != `DPoP error="invalid_request", algs="ES256"` {
				t.Fatalf("challenge = %q", got)
			}
			if registry.calls != 0 {
				t.Fatalf("registry called %d times", registry.calls)
			}
		})
	}
}

// recordingRegistry counts registrations and accepts them all.
type recordingRegistry struct{ calls int }

func (r *recordingRegistry) Register(context.Context, string, time.Time) error {
	r.calls++
	return nil
}

func (*recordingRegistry) RemoveExpired(context.Context, time.Time) (int, error) { return 0, nil }

func TestUserInfoDPoPLogsRegistryFailureByTypeOnly(t *testing.T) {
	t.Parallel()
	const marker = "registry-secret-marker"
	const jti = "proof-jti-marker"
	const token = "bound-token"
	now := time.Unix(1_800_000_000, 0)
	key := newUserInfoProofKey(t)

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := newDPoPUserInfoHandler(t, map[string]any{"jkt": key.thumbprint()}, markerRegistry{marker: marker}, now, logger)

	request := httptest.NewRequest(http.MethodGet, userInfoTestEndpoint, nil)
	request.Header.Set("Authorization", "DPoP "+token)
	request.Header.Set(wicket.DPoPHeaderName, key.proof(t, token, jti, now))
	recorder := httptest.NewRecorder()
	if err := handler.Process(recorder, request); err != nil {
		t.Fatalf("Process: %v", err)
	}

	if recorder.Code != http.StatusInternalServerError || recorder.Body.String() != "Internal Server Error\n" {
		t.Fatalf("status %d body %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "subject-1") || recorder.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("failure leaks claims or a challenge: %v %q", recorder.Header(), recorder.Body.String())
	}
	output := logs.String()
	if !strings.Contains(output, "DPoP proof could not be registered") || !strings.Contains(output, "error_type=") {
		t.Fatalf("registry failure not logged by type: %q", output)
	}
	for _, secret := range []string{marker, "key=", jti, token} {
		if strings.Contains(output, secret) {
			t.Fatalf("log output carries %q: %q", secret, output)
		}
	}
}

func TestUserInfoBearerRefusesBoundTokens(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	cases := map[string]struct {
		cnf        any
		wantOk     bool
		wantHeader string
	}{
		"unbound token":           {cnf: map[string]any{"other": "x"}, wantOk: true},
		"bound token":             {cnf: map[string]any{"jkt": "abc"}, wantHeader: `DPoP error="invalid_token", algs="ES256"`},
		"bound token as JSON":     {cnf: `{"jkt":"abc"}`, wantHeader: `DPoP error="invalid_token", algs="ES256"`},
		"numeric jkt":             {cnf: map[string]any{"jkt": 12.0}, wantHeader: `DPoP error="invalid_token", algs="ES256"`},
		"broken JSON":             {cnf: `{"jkt":`, wantHeader: `DPoP error="invalid_token", algs="ES256"`},
		"null confirmation":       {cnf: nil, wantHeader: `DPoP error="invalid_token", algs="ES256"`},
		"empty jkt":               {cnf: map[string]any{"jkt": ""}, wantHeader: `DPoP error="invalid_token", algs="ES256"`},
		"bound token with a cert": {cnf: map[string]any{"jkt": "abc", "x5t#S256": "def"}, wantHeader: `DPoP error="invalid_token", algs="ES256"`},
	}
	for name, tc := range cases {
		for _, enabled := range []bool{true, false} {
			t.Run(name+map[bool]string{true: " with DPoP", false: " without DPoP"}[enabled], func(t *testing.T) {
				t.Parallel()
				handler := newUserInfoHandlerUnderTest(userInfoResultWith(tc.cnf), map[string]any{"sub": "subject-1"})
				if enabled {
					options := dpop.Options{SigningAlgorithms: []string{"ES256"}}
					handler.SetDPoP(dpop.NewVerifier(options), replay.NewMemoryRegistry(), options, fixedClock{now: now})
				}
				request := httptest.NewRequest(http.MethodGet, userInfoTestEndpoint, nil)
				request.Header.Set("Authorization", "Bearer some-token")
				recorder := httptest.NewRecorder()
				if err := handler.Process(recorder, request); err != nil {
					t.Fatalf("Process: %v", err)
				}
				if tc.wantOk {
					if recorder.Code != http.StatusOK {
						t.Fatalf("status = %d, want 200", recorder.Code)
					}
					return
				}
				if recorder.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401", recorder.Code)
				}
				if enabled {
					if got := recorder.Header().Values("WWW-Authenticate"); len(got) != 1 || got[0] != tc.wantHeader {
						t.Fatalf("challenge = %q, want %q", got, tc.wantHeader)
					}
					return
				}
				// Without DPoP the existing bearer result answers.
				challenge := strings.Join(recorder.Header()["www-authenticate"], " ")
				if !strings.HasPrefix(challenge, "Bearer") || !strings.Contains(challenge, `error="invalid_token"`) {
					t.Fatalf("challenge = %q, want a bearer invalid_token", challenge)
				}
			})
		}
	}
}

func TestUserInfoWithoutDPoPKeepsTheDPoPSchemeUnrecognized(t *testing.T) {
	t.Parallel()
	key := newUserInfoProofKey(t)
	handler := newUserInfoHandlerUnderTest(userInfoResultWith(map[string]any{"jkt": key.thumbprint()}), map[string]any{"sub": "subject-1"})
	request := httptest.NewRequest(http.MethodGet, userInfoTestEndpoint, nil)
	request.Header.Set("Authorization", "DPoP bound-token")
	request.Header.Set(wicket.DPoPHeaderName, key.proof(t, "bound-token", "jti-1", time.Unix(1_800_000_000, 0)))
	recorder := httptest.NewRecorder()
	if err := handler.Process(recorder, request); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
	challenge := strings.Join(recorder.Header()["www-authenticate"], " ")
	if !strings.HasPrefix(challenge, "Bearer") || !strings.Contains(challenge, `error="invalid_token"`) {
		t.Fatalf("challenge = %q, want the bearer invalid_token", challenge)
	}
	if recorder.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("canonical challenge present: %q", recorder.Header().Get("WWW-Authenticate"))
	}
}
