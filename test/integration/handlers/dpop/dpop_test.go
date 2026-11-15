// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

func TestValidProofBindsTheAccessToken(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)

	t.Run("authorization code", func(t *testing.T) {
		code := s.authorizationCode(secretClientId)
		r := s.token(codeRequest(secretClientId, code), s.proof(key, proofSpec{}))
		cnf := s.requireIssued("code", r, false)
		require.Equal(t, map[string]any{"jkt": key.thumbprint()}, cnf)
	})
	t.Run("password grant", func(t *testing.T) {
		r := s.token(passwordRequest(secretClientId), s.proof(key, proofSpec{}))
		cnf := s.requireIssued("password", r, false)
		require.Equal(t, map[string]any{"jkt": key.thumbprint()}, cnf)
	})
	t.Run("client credentials", func(t *testing.T) {
		r := s.token(map[string][]string{
			"grant_type":    {wicket.GrantTypeClientCredentials},
			"client_id":     {secretClientId},
			"client_secret": {sharedSecret},
			"scope":         {scopeName},
		}, s.proof(key, proofSpec{}))
		cnf := s.requireIssued("client credentials", r, false)
		require.Equal(t, map[string]any{"jkt": key.thumbprint()}, cnf)
	})
	t.Run("reference token", func(t *testing.T) {
		r := s.token(passwordRequest(referenceClientId), s.proof(key, proofSpec{}))
		cnf := s.requireIssued("reference", r, true)
		require.Equal(t, map[string]any{"jkt": key.thumbprint()}, cnf)
	})
	t.Run("htu with default port, query and fragment", func(t *testing.T) {
		htu := strings.Replace(s.tokenEndpoint(), "http://", "HTTP://", 1) + "?x=1#f"
		r := s.token(passwordRequest(secretClientId), s.proof(key, proofSpec{htu: htu}))
		s.requireIssued("normalized htu", r, false)
		require.Equal(t, wicket.TokenResponseTypesDPoP, r.field("token_type"))
	})
	t.Run("discovery advertises the configured algorithms", func(t *testing.T) {
		require.Equal(t, []any{"ES256", "PS256"}, s.discovery()[wicket.DiscoveryDPoPSigningAlgValuesSupported])
	})
}

func TestWithoutProofTheResponseIsUnchanged(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	for _, clientId := range []string{secretClientId, publicClientId} {
		cnf := s.requireIssued(clientId, s.token(passwordRequest(clientId)), false)
		require.Nil(t, cnf)
	}
	cnf := s.requireIssued("reference", s.token(passwordRequest(referenceClientId)), true)
	require.Nil(t, cnf)
	require.Zero(t, s.registry.registers.Load())
}

func TestDPoPNotEnabledIgnoresTheHeader(t *testing.T) {
	s := newScene(t, sceneOptions{})
	key := newProofKey(t)

	r := s.token(passwordRequest(secretClientId), s.proof(key, proofSpec{}))
	cnf := s.requireIssued("valid proof ignored", r, false)
	require.Nil(t, cnf)

	r = s.token(passwordRequest(secretClientId), "not a proof", "another")
	cnf = s.requireIssued("garbage ignored", r, false)
	require.Nil(t, cnf)

	r = s.token(passwordRequest(referenceClientId), s.proof(key, proofSpec{}))
	require.Nil(t, s.requireIssued("reference", r, true))

	require.Zero(t, s.registry.registers.Load())
	_, advertised := s.discovery()[wicket.DiscoveryDPoPSigningAlgValuesSupported]
	require.False(t, advertised)

	// A client requiring DPoP is an invalid configuration while DPoP is not
	// enabled; it is refused, not served bearer tokens.
	requireError(t, "required while not enabled", s.token(passwordRequest(requiredClientId), s.proof(key, proofSpec{})), "invalid_client")
}

func TestClientRequiringDPoP(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)

	r := s.token(passwordRequest(requiredClientId))
	requireError(t, "no proof", r, "invalid_request")
	require.Equal(t, "DPoP proof required", r.field("error_description"))
	require.Zero(t, s.registry.registers.Load())

	cnf := s.requireIssued("with proof", s.token(passwordRequest(requiredClientId), s.proof(key, proofSpec{})), false)
	require.Equal(t, key.thumbprint(), cnf["jkt"])

	// Front channel access tokens cannot carry a proof.
	requireError(t, "browser client", s.token(passwordRequest(requiredBrowserClientId), s.proof(key, proofSpec{})), "invalid_client")
}

func TestInvalidProofsAreRefusedBeforeRegistration(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	other := newProofKey(t)

	valid := s.proof(key, proofSpec{})
	segments := strings.Split(valid, ".")
	cases := map[string][]string{
		"two proofs":            {s.proof(key, proofSpec{}), s.proof(key, proofSpec{})},
		"not a compact JWS":     {segments[0] + "." + segments[1]},
		"typ":                   {s.proof(key, proofSpec{typ: "JWT"})},
		"alg not configured":    {s.proof(key, proofSpec{alg: "ES384"})},
		"alg none":              {s.proof(key, proofSpec{alg: "none"})},
		"jwk missing":           {s.proof(key, proofSpec{withoutJ: true})},
		"jwk with private key":  {s.proof(key, proofSpec{headers: map[string]any{"jwk": privateJwk(key)}})},
		"jwk type for alg":      {s.proof(key, proofSpec{alg: "PS256"})},
		"alg HS256":             {s.proof(key, proofSpec{alg: "HS256"})},
		"crit present":          {s.proof(key, proofSpec{headers: map[string]any{"crit": []string{"exp"}, "exp": 1}})},
		"htm missing":           {s.proof(key, proofSpec{extra: map[string]any{"htm": nil}})},
		"htu missing":           {s.proof(key, proofSpec{extra: map[string]any{"htu": nil}})},
		"signed by another key": {s.proof(key, proofSpec{signer: other.private})},
		"jti missing":           {s.proof(key, proofSpec{extra: map[string]any{"jti": nil}})},
		"jti too long":          {s.proof(key, proofSpec{jti: strings.Repeat("j", 257)})},
		"htm":                   {s.proof(key, proofSpec{htm: http.MethodGet})},
		"htu other endpoint":    {s.proof(key, proofSpec{htu: s.pipeline.TestServer.URL + integration_common.UserInfoEndpoint})},
		"htu other host":        {s.proof(key, proofSpec{htu: "http://other.example" + integration_common.TokenEndpoint})},
		"iat too old":           {s.proof(key, proofSpec{iat: time.Now().Add(-10 * time.Minute)})},
		"iat in the future":     {s.proof(key, proofSpec{iat: time.Now().Add(10 * time.Minute)})},
		"iat missing":           {s.proof(key, proofSpec{extra: map[string]any{"iat": nil}})},
	}

	code := s.authorizationCode(secretClientId)
	for name, proofs := range cases {
		requireError(t, name+" (password)", s.token(passwordRequest(secretClientId), proofs...), "invalid_dpop_proof")
		// The authorization code is not consumed by a refused proof.
		requireError(t, name+" (code)", s.token(codeRequest(secretClientId, code), proofs...), "invalid_dpop_proof")
	}
	require.Zero(t, s.registry.registers.Load(), "a refused proof reached the replay registry")

	cnf := s.requireIssued("code after the refusals", s.token(codeRequest(secretClientId, code), valid), false)
	require.Equal(t, key.thumbprint(), cnf["jkt"])
	require.EqualValues(t, 1, s.registry.registers.Load())
}

// privateJwk returns the JWK of key including its private member d.
func privateJwk(key proofKey) map[string]any {
	members := key.jwk()
	d := make([]byte, 32)
	key.private.D.FillBytes(d)
	members["d"] = base64.RawURLEncoding.EncodeToString(d)
	return members
}

func TestReplayedProofIsRefused(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	other := newProofKey(t)

	proof := s.proof(key, proofSpec{jti: "shared-jti"})
	s.requireIssued("first use", s.token(passwordRequest(secretClientId), proof), false)
	requireError(t, "replay", s.token(passwordRequest(secretClientId), proof), "invalid_dpop_proof")
	requireError(t, "same key, same jti, new proof", s.token(passwordRequest(secretClientId), s.proof(key, proofSpec{jti: "shared-jti"})), "invalid_dpop_proof")

	// The key is qualified by the proof key: the same jti under another key
	// is a different proof.
	cnf := s.requireIssued("other key", s.token(passwordRequest(secretClientId), s.proof(other, proofSpec{jti: "shared-jti"})), false)
	require.Equal(t, other.thumbprint(), cnf["jkt"])

	require.EqualValues(t, 4, s.registry.registers.Load())
	s.registry.mu.Lock()
	keys := append([]string(nil), s.registry.keys...)
	s.registry.mu.Unlock()
	require.Equal(t, keys[0], keys[1])
	require.Equal(t, keys[0], keys[2])
	require.NotEqual(t, keys[0], keys[3])
	for _, registered := range keys {
		require.NotContains(t, registered, "shared-jti")
		require.Len(t, registered, 64)
	}
}

func TestRegistryFailureIsAFixedServerError(t *testing.T) {
	const marker = "registry-down-marker"
	s := newScene(t, sceneOptions{enable: true, registry: failingRegistry{err: errors.New(marker)}})
	key := newProofKey(t)

	code := s.authorizationCode(secretClientId)
	r := s.token(codeRequest(secretClientId, code), s.proof(key, proofSpec{}))
	requireFixedServerError(t, "code", r)
	require.NotContains(t, r.body, marker)

	requireFixedServerError(t, "password", s.token(passwordRequest(secretClientId), s.proof(key, proofSpec{})))
	// Without a proof nothing is registered and the request is served.
	s.requireIssued("no proof", s.token(passwordRequest(secretClientId)), false)
}

func TestPublicClientRefreshTokenIsBoundToTheProofKey(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	other := newProofKey(t)

	issued := s.token(passwordRequest(publicClientId), s.proof(key, proofSpec{}))
	s.requireIssued("issue", issued, false)
	refreshToken := issued.field("refresh_token")
	require.NotEmpty(t, refreshToken)

	requireError(t, "refresh without proof", s.token(refreshRequest(publicClientId, refreshToken)), "invalid_grant")
	requireError(t, "refresh with another key", s.token(refreshRequest(publicClientId, refreshToken), s.proof(other, proofSpec{})), "invalid_grant")

	refreshed := s.token(refreshRequest(publicClientId, refreshToken), s.proof(key, proofSpec{}))
	cnf := s.requireIssued("refresh with the same key", refreshed, false)
	require.Equal(t, key.thumbprint(), cnf["jkt"])
	require.Equal(t, refreshToken, refreshed.field("refresh_token"))

	// The binding outlived the redemption and the refusals.
	requireError(t, "refresh with another key again", s.token(refreshRequest(publicClientId, refreshToken), s.proof(other, proofSpec{})), "invalid_grant")
	again := s.token(refreshRequest(publicClientId, refreshToken), s.proof(key, proofSpec{}))
	require.Equal(t, key.thumbprint(), s.requireIssued("refresh again", again, false)["jkt"])
}

func TestPublicClientRefreshTokenWithoutProofStaysUnbound(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)

	issued := s.token(passwordRequest(publicClientId))
	require.Nil(t, s.requireIssued("issue without proof", issued, false))
	refreshToken := issued.field("refresh_token")

	// An unbound refresh token is not bound afterwards.
	cnf := s.requireIssued("refresh with proof", s.token(refreshRequest(publicClientId, refreshToken), s.proof(key, proofSpec{})), false)
	require.Equal(t, key.thumbprint(), cnf["jkt"])
	require.Nil(t, s.requireIssued("refresh without proof", s.token(refreshRequest(publicClientId, refreshToken)), false))
}

func TestConfidentialClientRefreshTokenIsNotBound(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	other := newProofKey(t)

	for _, clientId := range []string{secretClientId, referenceClientId} {
		t.Run(clientId, func(t *testing.T) {
			reference := clientId == referenceClientId
			issued := s.token(passwordRequest(clientId), s.proof(key, proofSpec{}))
			s.requireIssued("issue", issued, reference)
			refreshToken := issued.field("refresh_token")

			cnf := s.requireIssued("refresh with another key", s.token(refreshRequest(clientId, refreshToken), s.proof(other, proofSpec{})), reference)
			require.Equal(t, other.thumbprint(), cnf["jkt"])
			require.Nil(t, s.requireIssued("refresh without proof", s.token(refreshRequest(clientId, refreshToken)), reference))
		})
	}
}

func TestCertificateAndProofBindingCombine(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, mutualTls: true})
	key := newProofKey(t)

	r := s.token(passwordRequest(certificateClientId), s.proof(key, proofSpec{}))
	cnf := s.requireIssued("both", r, false)
	digest := sha256.Sum256(s.certificate.Raw)
	require.Equal(t, map[string]any{
		"x5t#S256": base64.RawURLEncoding.EncodeToString(digest[:]),
		"jkt":      key.thumbprint(),
	}, cnf)

	// Without a proof only the certificate binding remains, and the token
	// type stays Bearer.
	cnf = s.requireIssued("certificate only", s.token(passwordRequest(certificateClientId)), false)
	require.Equal(t, map[string]any{"x5t#S256": base64.RawURLEncoding.EncodeToString(digest[:])}, cnf)

	// At the mutual TLS alias the proof names the alias URI.
	alias := s.pipeline.TestServer.URL + "/" + wicket.ProtocolRoutePathsMtlsToken
	r = s.tokenAt(alias, passwordRequest(certificateClientId), s.proof(key, proofSpec{htu: alias}))
	require.Equal(t, key.thumbprint(), s.requireIssued("alias", r, false)["jkt"])
	requireError(t, "alias with the main route's htu", s.tokenAt(alias, passwordRequest(certificateClientId), s.proof(key, proofSpec{})), "invalid_dpop_proof")
}
