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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/dpop"
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// markerRegistry fails every registration with an error carrying the key it
// was given and a marker.
type markerRegistry struct{ marker string }

func (r markerRegistry) Register(_ context.Context, key string, _ time.Time) error {
	return errors.New(r.marker + " key=" + key)
}

func (markerRegistry) RemoveExpired(context.Context, time.Time) (int, error) { return 0, nil }

// signedTestProof returns an ES256 DPoP proof for a POST to endpoint.
func signedTestProof(t *testing.T, endpoint string, jti string, now time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	x, y := make([]byte, 32), make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	header, _ := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256",
		"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": encode(x), "y": encode(y)},
	})
	claims, _ := json.Marshal(map[string]any{"jti": jti, "htm": http.MethodPost, "htu": endpoint, "iat": now.Unix()})
	input := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + encode(signature)
}

func TestTokenHandlerLogsRegistryFailureByTypeOnly(t *testing.T) {
	t.Parallel()
	const marker = "registry-secret-marker"
	const jti = "proof-jti-marker"
	now := time.Unix(1_800_000_000, 0)

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := NewTokenHandler(
		&fakeClientSecretValidator{result: successClientResult()},
		&fakeTokenRequestValidator{result: &validators_models.TokenRequestValidationResult{}},
		&fakeTokenResponseGenerator{response: &responses_models.TokenResponse{}},
		logger,
	)
	options := dpop.Options{}
	handler.SetDPoP(dpop.NewVerifier(options), markerRegistry{marker: marker}, options, fixedClock{now: now})

	request := newTokenForm()
	request.Header.Set(wicket.DPoPHeaderName, signedTestProof(t, "https://wicket.test"+wicket.ProtocolRoutePathsToken, jti, now))
	recorder := httptest.NewRecorder()
	if err := handler.Process(recorder, request); err != nil {
		t.Fatalf("Process: %v", err)
	}

	if recorder.Code != http.StatusInternalServerError || recorder.Body.String() != "Internal Server Error\n" {
		t.Fatalf("status %d body %q", recorder.Code, recorder.Body.String())
	}
	output := logs.String()
	if !strings.Contains(output, "DPoP proof could not be registered") || !strings.Contains(output, "error_type=") {
		t.Fatalf("registry failure not logged by type: %q", output)
	}
	for _, secret := range []string{marker, "key=", jti} {
		if strings.Contains(output, secret) {
			t.Fatalf("log output carries %q: %q", secret, output)
		}
	}
}
