// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"bytes"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	wicket_dpop "github.com/gonewx/wicket/dpop"
)

func nonceKey(id string, fill byte) wicket_dpop.NonceKey {
	return wicket_dpop.NonceKey{Id: id, Secret: bytes.Repeat([]byte{fill}, 32)}
}

func nonceKeys(t *testing.T, current wicket_dpop.NonceKey, previous ...wicket_dpop.NonceKey) wicket_dpop.NonceKeySource {
	t.Helper()
	source, err := wicket_dpop.NewStaticNonceKeys(current, previous...)
	require.NoError(t, err)
	return source
}

// surface is the surface the scene's server issues nonces for.
func (s *scene) surface() string {
	s.t.Helper()
	issuer, _ := s.discovery()["issuer"].(string)
	require.NotEmpty(s.t, issuer)
	return "authorization-server " + issuer
}

// nonceIssuedBy returns a nonce issued for the scene's server by another
// replica holding keys, at the given instant.
func (s *scene) nonceIssuedBy(keys wicket_dpop.NonceKeySource, surface string, at time.Time) string {
	s.t.Helper()
	nonce, err := wicket_dpop.NewNonceSealer(keys, wicket_dpop.Options{}).Issue(surface, at)
	require.NoError(s.t, err)
	return nonce
}

func requireUseNonce(t *testing.T, name string, r reply) string {
	t.Helper()
	requireError(t, name, r, wicket.TokenErrorsUseDPoPNonce.Error())
	nonce := r.header.Get(wicket.DPoPNonceHeaderName)
	require.NotEmptyf(t, nonce, "%s: no DPoP-Nonce header", name)
	return nonce
}

func withNonce(nonce string) proofSpec {
	return proofSpec{extra: map[string]any{"nonce": nonce}}
}

func TestServerNonceChallengeAndRetry(t *testing.T) {
	keys := nonceKeys(t, nonceKey("k1", 1))
	s := newScene(t, sceneOptions{enable: true, nonceKeys: keys})
	key := newProofKey(t)
	code := s.authorizationCode(secretClientId)

	// The first request is challenged; neither the code nor any proof
	// identifier is consumed.
	nonce := requireUseNonce(t, "first request", s.token(codeRequest(secretClientId, code), s.proof(key, proofSpec{})))
	require.Zero(t, s.registry.registers.Load())

	// The retry with the nonce redeems the same code.
	r := s.token(codeRequest(secretClientId, code), s.proof(key, withNonce(nonce)))
	cnf := s.requireIssued("retry", r, false)
	require.Equal(t, map[string]any{"jkt": key.thumbprint()}, cnf)
	require.NotEmpty(t, r.header.Get(wicket.DPoPNonceHeaderName), "success without a fresh nonce")
	require.EqualValues(t, 1, s.registry.registers.Load())

	// A nonce stays usable for later proofs within its lifetime.
	s.requireIssued("reuse", s.token(passwordRequest(secretClientId), s.proof(key, withNonce(r.header.Get(wicket.DPoPNonceHeaderName)))), false)
}

func TestServerNonceRefusals(t *testing.T) {
	keys := nonceKeys(t, nonceKey("k1", 1))
	s := newScene(t, sceneOptions{enable: true, nonceKeys: keys})
	key := newProofKey(t)
	surface := s.surface()

	cases := map[string]string{
		"expired":           s.nonceIssuedBy(keys, surface, time.Now().Add(-10*time.Minute)),
		"issued in future":  s.nonceIssuedBy(keys, surface, time.Now().Add(10*time.Minute)),
		"other surface":     s.nonceIssuedBy(keys, "authorization-server https://other.example/", time.Now()),
		"unknown key":       s.nonceIssuedBy(nonceKeys(t, nonceKey("k9", 9)), surface, time.Now()),
		"same id other key": s.nonceIssuedBy(nonceKeys(t, nonceKey("k1", 2)), surface, time.Now()),
		"not a nonce":       "garbage",
	}
	for name, nonce := range cases {
		t.Run(name, func(t *testing.T) {
			code := s.authorizationCode(secretClientId)
			before := s.registry.registers.Load()
			fresh := requireUseNonce(t, name, s.token(codeRequest(secretClientId, code), s.proof(key, withNonce(nonce))))
			require.NotEqual(t, nonce, fresh)
			require.Equal(t, before, s.registry.registers.Load())
			// The challenge burned nothing: the fresh nonce redeems the code.
			s.requireIssued(name+" retry", s.token(codeRequest(secretClientId, code), s.proof(key, withNonce(fresh))), false)
		})
	}
}

func TestServerNonceSharedAcrossReplicasAndRotation(t *testing.T) {
	old := nonceKey("old", 1)
	current := nonceKey("current", 2)
	s := newScene(t, sceneOptions{enable: true, nonceKeys: nonceKeys(t, current, old)})
	key := newProofKey(t)
	surface := s.surface()

	for name, keys := range map[string]wicket_dpop.NonceKeySource{
		"replica with the same keys":         nonceKeys(t, current, old),
		"replica still issuing with old key": nonceKeys(t, old),
	} {
		nonce := s.nonceIssuedBy(keys, surface, time.Now())
		s.requireIssued(name, s.token(passwordRequest(secretClientId), s.proof(key, withNonce(nonce))), false)
	}
}

func TestServerNonceHeaderOnlyForDPoPRequests(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, nonceKeys: nonceKeys(t, nonceKey("k1", 1))})
	key := newProofKey(t)

	plain := s.token(passwordRequest(secretClientId))
	require.Nil(t, s.requireIssued("without DPoP", plain, false))
	require.Empty(t, plain.header.Get(wicket.DPoPNonceHeaderName))

	invalid := s.token(passwordRequest(secretClientId), s.proof(key, proofSpec{htm: http.MethodGet}))
	requireError(t, "invalid proof", invalid, wicket.TokenErrorsInvalidDPoPProof.Error())
	require.NotEmpty(t, invalid.header.Get(wicket.DPoPNonceHeaderName))
	require.Zero(t, s.registry.registers.Load())
}

func TestServerNonceOffLeavesTheEndpointAsItWas(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	r := s.token(passwordRequest(secretClientId), s.proof(key, proofSpec{}))
	s.requireIssued("no nonce required", r, false)
	require.Empty(t, r.header.Get(wicket.DPoPNonceHeaderName))
	invalid := s.token(passwordRequest(secretClientId), s.proof(key, proofSpec{htm: http.MethodGet}))
	requireError(t, "invalid proof", invalid, wicket.TokenErrorsInvalidDPoPProof.Error())
	require.Empty(t, invalid.header.Get(wicket.DPoPNonceHeaderName))
}

func TestServerNonceKeySourceFailureIsAServerError(t *testing.T) {
	source := &switchingNonceKeys{keys: nonceKeys(t, nonceKey("k1", 1))}
	s := newScene(t, sceneOptions{enable: true, nonceKeys: source})
	key := newProofKey(t)

	source.broken.Store(true)
	r := s.token(passwordRequest(secretClientId), s.proof(key, proofSpec{}))
	requireFixedServerError(t, "key source fails", r)
	require.Empty(t, r.header.Get(wicket.DPoPNonceHeaderName))
	require.Zero(t, s.registry.registers.Load())
}

// switchingNonceKeys provides keys until broken is set, then invalid ones.
type switchingNonceKeys struct {
	keys   wicket_dpop.NonceKeySource
	broken atomic.Bool
}

func (s *switchingNonceKeys) NonceKeys() (wicket_dpop.NonceKey, []wicket_dpop.NonceKey, error) {
	if s.broken.Load() {
		return wicket_dpop.NonceKey{Id: "k1", Secret: []byte("short")}, nil, nil
	}
	return s.keys.NonceKeys()
}

func TestServerNonceAcceptedAcrossMutualTlsAlias(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, mutualTls: true, nonceKeys: nonceKeys(t, nonceKey("k1", 1))})
	key := newProofKey(t)
	alias := s.pipeline.TestServer.URL + "/" + wicket.ProtocolRoutePathsMtlsToken

	// A nonce obtained on the main route redeems at the alias.
	mainNonce := requireUseNonce(t, "main route challenge", s.token(passwordRequest(certificateClientId), s.proof(key, proofSpec{})))
	r := s.tokenAt(alias, passwordRequest(certificateClientId), s.proof(key, proofSpec{htu: alias, extra: map[string]any{"nonce": mainNonce}}))
	s.requireIssued("alias with the main route's nonce", r, false)

	// A nonce obtained at the alias redeems on the main route.
	aliasNonce := requireUseNonce(t, "alias challenge", s.tokenAt(alias, passwordRequest(certificateClientId), s.proof(key, proofSpec{htu: alias})))
	r = s.token(passwordRequest(certificateClientId), s.proof(key, withNonce(aliasNonce)))
	s.requireIssued("main route with the alias's nonce", r, false)
}
