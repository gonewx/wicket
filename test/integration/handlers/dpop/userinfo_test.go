// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

// The challenges a scene answers with; it accepts ES256 and PS256 proofs.
const (
	challengeInvalidProof   = `DPoP error="invalid_dpop_proof", algs="ES256 PS256"`
	challengeInvalidToken   = `DPoP error="invalid_token", algs="ES256 PS256"`
	challengeInvalidRequest = `DPoP error="invalid_request", algs="ES256 PS256"`
	challengeExpiredToken   = `DPoP error="invalid_token", error_description="The access token expired", algs="ES256 PS256"`
)

func (s *scene) userInfoEndpoint() string {
	return s.pipeline.TestServer.URL + integration_common.UserInfoEndpoint
}

// tokenHash is the ath of token, computed by the test itself.
func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// userInfoProof signs a GET proof for the userinfo endpoint carrying the
// ath of token; spec overrides fields as for proof.
func (s *scene) userInfoProof(key proofKey, token string, spec proofSpec) string {
	s.t.Helper()
	if spec.htm == "" {
		spec.htm = http.MethodGet
	}
	if spec.htu == "" {
		spec.htu = s.userInfoEndpoint()
	}
	extra := map[string]any{"ath": tokenHash(token)}
	for name, value := range spec.extra {
		extra[name] = value
	}
	spec.extra = extra
	return s.proof(key, spec)
}

// userInfoRequest describes one userinfo call.
type userInfoRequest struct {
	// authorization is the whole Authorization header; empty sends none.
	authorization string
	proofs        []string
	// form, when set, is posted as the form body.
	form url.Values
	// withCertificate presents the scene's client certificate.
	withCertificate bool
}

func (s *scene) userInfo(call userInfoRequest) reply {
	s.t.Helper()
	method := http.MethodGet
	var body *strings.Reader
	if call.form != nil {
		method = http.MethodPost
		body = strings.NewReader(call.form.Encode())
	} else {
		body = strings.NewReader("")
	}
	request, err := http.NewRequest(method, s.userInfoEndpoint(), body)
	require.NoError(s.t, err)
	if call.form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if call.authorization != "" {
		request.Header.Set("Authorization", call.authorization)
	}
	for _, proof := range call.proofs {
		request.Header.Add(wicket.DPoPHeaderName, proof)
	}
	if call.withCertificate && s.certificate != nil {
		request.Header.Set(certificateHeader, base64.StdEncoding.EncodeToString(s.certificate.Raw))
	}
	return s.do(request)
}

// dpopCall presents token with the DPoP scheme and a valid proof of key.
func (s *scene) dpopCall(key proofKey, token string) reply {
	s.t.Helper()
	return s.userInfo(userInfoRequest{authorization: "DPoP " + token, proofs: []string{s.userInfoProof(key, token, proofSpec{})}})
}

func requireUserInfo(t *testing.T, name string, r reply) {
	t.Helper()
	require.Equalf(t, http.StatusOK, r.status, "%s: body %s header %v", name, r.body, r.header)
	require.Equalf(t, subjectId, r.field("sub"), "%s: body %s", name, r.body)
}

// requireChallenge asserts the exact DPoP challenge on the wire.
func requireChallenge(t *testing.T, name string, r reply, status int, challenge string) {
	t.Helper()
	require.Equalf(t, status, r.status, "%s: body %s header %v", name, r.body, r.header)
	require.Equalf(t, []string{challenge}, r.header.Values("WWW-Authenticate"), "%s", name)
	require.Equalf(t, "no-store", r.header.Get("Cache-Control"), "%s", name)
	require.Emptyf(t, r.body, "%s", name)
}

// storeUserInfoReference places a reference access token for bob issued to
// referenceClientId carrying the given cnf claim values, the way a token
// store adapter may hand them back.
func (s *scene) storeUserInfoReference(handle string, creation time.Time, cnf ...any) {
	s.t.Helper()
	tokenClaims := []*claimspkg.Claim{
		claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesSubject), claimspkg.WithClaimValue(subjectId)),
		claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesClientId), claimspkg.WithClaimValue(referenceClientId)),
		claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesScope), claimspkg.WithClaimValue(wicket.StandardScopesOpenId)),
		claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesScope), claimspkg.WithClaimValue(scopeName)),
	}
	for _, value := range cnf {
		tokenClaims = append(tokenClaims,
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesConfirmation), claimspkg.WithClaimValue(value)))
	}
	token := &storage_models.Token{
		Issuer:          s.pipeline.TestServer.URL,
		Audiences:       []string{apiName},
		CreationTime:    creation.UTC(),
		Lifetime:        3600,
		Type:            wicket.TokenTypesAccessToken,
		ClientId:        referenceClientId,
		AccessTokenType: wicket.AccessTokenTypeReference,
		Claims:          tokenClaims,
	}
	require.NoError(s.t, s.referenceTokens.StoreReferenceToken(context.Background(), handle, token))
}

// issue returns an access token issued to clientId by the password grant,
// bound to key when key is not nil.
func (s *scene) issue(clientId string, key *proofKey) string {
	s.t.Helper()
	var proofs []string
	if key != nil {
		proofs = append(proofs, s.proof(*key, proofSpec{}))
	}
	r := s.token(passwordRequest(clientId), proofs...)
	require.Equalf(s.t, http.StatusOK, r.status, "issue: %s", r.body)
	token := r.field("access_token")
	require.NotEmpty(s.t, token)
	return token
}

func TestUserInfoAcceptsDPoPBoundTokens(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)

	t.Run("bound JWT", func(t *testing.T) {
		token := s.issue(secretClientId, &key)
		requireUserInfo(t, "bound JWT", s.dpopCall(key, token))
	})
	t.Run("bound reference token", func(t *testing.T) {
		token := s.issue(referenceClientId, &key)
		require.Len(t, strings.Split(token, "."), 1)
		requireUserInfo(t, "bound reference", s.dpopCall(key, token))
	})
	t.Run("scheme in lower case", func(t *testing.T) {
		token := s.issue(secretClientId, &key)
		requireUserInfo(t, "lower case", s.userInfo(userInfoRequest{
			authorization: "dpop " + token, proofs: []string{s.userInfoProof(key, token, proofSpec{})},
		}))
	})
	t.Run("claims as for a bearer token", func(t *testing.T) {
		bound := s.dpopCall(key, s.issue(secretClientId, &key))
		unbound := s.userInfo(userInfoRequest{authorization: "Bearer " + s.issue(secretClientId, nil)})
		requireUserInfo(t, "bound", bound)
		requireUserInfo(t, "unbound", unbound)
		require.JSONEq(t, unbound.body, bound.body)
	})
	t.Run("POST without a form token", func(t *testing.T) {
		token := s.issue(secretClientId, &key)
		r := s.userInfo(userInfoRequest{
			authorization: "DPoP " + token,
			proofs:        []string{s.userInfoProof(key, token, proofSpec{htm: http.MethodPost})},
			form:          url.Values{"other": {"x"}},
		})
		requireUserInfo(t, "POST", r)
	})
	t.Run("JSON text confirmation", func(t *testing.T) {
		s.storeUserInfoReference("json-text-bound", time.Now(), `{"jkt":"`+key.thumbprint()+`"}`)
		requireUserInfo(t, "DPoP", s.dpopCall(key, "json-text-bound"))
		requireChallenge(t, "bearer", s.userInfo(userInfoRequest{authorization: "Bearer json-text-bound"}),
			http.StatusUnauthorized, challengeInvalidToken)
	})
}

func TestUserInfoRejectsInvalidDPoPRequests(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	other := newProofKey(t)
	token := s.issue(secretClientId, &key)
	unbound := s.issue(secretClientId, nil)
	dpopWith := func(proofs ...string) userInfoRequest {
		return userInfoRequest{authorization: "DPoP " + token, proofs: proofs}
	}

	cases := map[string]struct {
		call      userInfoRequest
		status    int
		challenge string
	}{
		"ath of another token":    {call: dpopWith(s.userInfoProof(key, unbound, proofSpec{})), status: 401, challenge: challengeInvalidProof},
		"ath missing":             {call: dpopWith(s.userInfoProof(key, token, proofSpec{extra: map[string]any{"ath": nil}})), status: 401, challenge: challengeInvalidProof},
		"ath not a string":        {call: dpopWith(s.userInfoProof(key, token, proofSpec{extra: map[string]any{"ath": 12}})), status: 401, challenge: challengeInvalidProof},
		"htm POST":                {call: dpopWith(s.userInfoProof(key, token, proofSpec{htm: http.MethodPost})), status: 401, challenge: challengeInvalidProof},
		"htu token endpoint":      {call: dpopWith(s.userInfoProof(key, token, proofSpec{htu: s.tokenEndpoint()})), status: 401, challenge: challengeInvalidProof},
		"no proof":                {call: dpopWith(), status: 401, challenge: challengeInvalidProof},
		"two proofs":              {call: dpopWith(s.userInfoProof(key, token, proofSpec{}), s.userInfoProof(key, token, proofSpec{})), status: 401, challenge: challengeInvalidProof},
		"proof of another key":    {call: dpopWith(s.userInfoProof(other, token, proofSpec{})), status: 401, challenge: challengeInvalidToken},
		"unbound token":           {call: userInfoRequest{authorization: "DPoP " + unbound, proofs: []string{s.userInfoProof(key, unbound, proofSpec{})}}, status: 401, challenge: challengeInvalidToken},
		"invalid token":           {call: userInfoRequest{authorization: "DPoP not-a-token", proofs: []string{s.userInfoProof(key, "not-a-token", proofSpec{})}}, status: 401, challenge: challengeInvalidToken},
		"bound token as bearer":   {call: userInfoRequest{authorization: "Bearer " + token}, status: 401, challenge: challengeInvalidToken},
		"bearer with a proof":     {call: userInfoRequest{authorization: "Bearer " + token, proofs: []string{s.userInfoProof(key, token, proofSpec{})}}, status: 401, challenge: challengeInvalidToken},
		"bound token in the form": {call: userInfoRequest{form: url.Values{"access_token": {token}}}, status: 401, challenge: challengeInvalidToken},
		"scheme without token":    {call: userInfoRequest{authorization: "DPoP", proofs: []string{s.userInfoProof(key, token, proofSpec{})}}, status: 400, challenge: challengeInvalidRequest},
		"token with a space":      {call: userInfoRequest{authorization: "DPoP " + token + " x", proofs: []string{s.userInfoProof(key, token, proofSpec{})}}, status: 400, challenge: challengeInvalidRequest},
		"token also in the form":  {call: userInfoRequest{authorization: "DPoP " + token, proofs: []string{s.userInfoProof(key, token, proofSpec{htm: http.MethodPost})}, form: url.Values{"access_token": {token}}}, status: 400, challenge: challengeInvalidRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			before := s.registry.registers.Load()
			requireChallenge(t, name, s.userInfo(tc.call), tc.status, tc.challenge)
			require.Equalf(t, before, s.registry.registers.Load(), "%s: a rejected request registered its proof", name)
		})
	}

	t.Run("unbound token as bearer with a proof", func(t *testing.T) {
		r := s.userInfo(userInfoRequest{authorization: "Bearer " + unbound, proofs: []string{s.userInfoProof(key, unbound, proofSpec{})}})
		requireUserInfo(t, "unbound bearer", r)
	})
}

func TestUserInfoRejectsAReplayedProof(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	token := s.issue(secretClientId, &key)
	proof := s.userInfoProof(key, token, proofSpec{})
	call := userInfoRequest{authorization: "DPoP " + token, proofs: []string{proof}}

	requireUserInfo(t, "first", s.userInfo(call))
	requireChallenge(t, "replay", s.userInfo(call), http.StatusUnauthorized, challengeInvalidProof)
}

func TestUserInfoRejectsMalformedConfirmations(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	cases := map[string][]any{
		"broken JSON text":  {`{"jkt":`},
		"numeric jkt":       {map[string]any{"jkt": 12.0}},
		"empty jkt":         {map[string]any{"jkt": ""}},
		"two confirmations": {map[string]any{"jkt": key.thumbprint()}, map[string]any{"jkt": key.thumbprint()}},
	}
	for name, cnf := range cases {
		t.Run(name, func(t *testing.T) {
			handle := "malformed-" + strings.ReplaceAll(name, " ", "-")
			s.storeUserInfoReference(handle, time.Now(), cnf...)
			requireChallenge(t, name+" DPoP", s.dpopCall(key, handle), http.StatusUnauthorized, challengeInvalidToken)
			requireChallenge(t, name+" bearer", s.userInfo(userInfoRequest{authorization: "Bearer " + handle}),
				http.StatusUnauthorized, challengeInvalidToken)
		})
	}
}

func TestUserInfoAnswersAnExpiredDPoPToken(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	s.storeUserInfoReference("expired-bound", time.Now().Add(-2*time.Hour), map[string]any{"jkt": key.thumbprint()})
	requireChallenge(t, "expired", s.dpopCall(key, "expired-bound"), http.StatusUnauthorized, challengeExpiredToken)
}

func TestUserInfoChecksBothBindings(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, mutualTls: true})
	key := newProofKey(t)
	s.storeUserInfoReference("double-bound", time.Now(), map[string]any{
		"jkt":      key.thumbprint(),
		"x5t#S256": certificateThumbprint(s),
	})

	proof := s.userInfoProof(key, "double-bound", proofSpec{})
	before := s.registry.registers.Load()
	r := s.userInfo(userInfoRequest{authorization: "DPoP double-bound", proofs: []string{proof}})
	requireChallenge(t, "without certificate", r, http.StatusUnauthorized, challengeInvalidToken)
	require.Equal(t, before, s.registry.registers.Load(), "a certificate mismatch registered the proof")

	// The refused proof was not registered, so it is still accepted.
	r = s.userInfo(userInfoRequest{authorization: "DPoP double-bound", proofs: []string{proof}, withCertificate: true})
	requireUserInfo(t, "with certificate", r)
}

func certificateThumbprint(s *scene) string {
	digest := sha256.Sum256(s.certificate.Raw)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func TestUserInfoRegistryFailureIsAServerError(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, registry: failingRegistry{err: errors.New("registry down")}})
	key := newProofKey(t)
	s.storeUserInfoReference("registry-failure", time.Now(), map[string]any{"jkt": key.thumbprint()})
	r := s.dpopCall(key, "registry-failure")
	requireFixedServerError(t, "registry failure", r)
	require.NotContains(t, r.body, subjectId)
}

func TestUserInfoIgnoresServerNonces(t *testing.T) {
	keys := nonceKeys(t, nonceKey("k1", 1))
	s := newScene(t, sceneOptions{enable: true, nonceKeys: keys})
	key := newProofKey(t)
	s.storeUserInfoReference("nonce-bound", time.Now(), map[string]any{"jkt": key.thumbprint()})
	call := func(extra map[string]any) reply {
		return s.userInfo(userInfoRequest{
			authorization: "DPoP nonce-bound", proofs: []string{s.userInfoProof(key, "nonce-bound", proofSpec{extra: extra})},
		})
	}

	requireUserInfo(t, "no nonce", call(nil))
	requireUserInfo(t, "any nonce", call(map[string]any{"nonce": "not-a-server-nonce"}))
	requireChallenge(t, "empty nonce", call(map[string]any{"nonce": ""}), http.StatusUnauthorized, challengeInvalidProof)
	requireChallenge(t, "numeric nonce", call(map[string]any{"nonce": 12}), http.StatusUnauthorized, challengeInvalidProof)
}

func TestUserInfoWithoutDPoP(t *testing.T) {
	s := newScene(t, sceneOptions{})
	key := newProofKey(t)
	s.storeUserInfoReference("bound-without-dpop", time.Now(), map[string]any{"jkt": key.thumbprint()})
	s.storeUserInfoReference("unbound-without-dpop", time.Now())

	// The bearer result cannot carry its challenge over HTTP, so only the
	// status is asserted.
	r := s.dpopCall(key, "bound-without-dpop")
	require.Equal(t, http.StatusUnauthorized, r.status, r.body)
	r = s.userInfo(userInfoRequest{authorization: "Bearer bound-without-dpop"})
	require.Equal(t, http.StatusUnauthorized, r.status, r.body)
	requireUserInfo(t, "unbound bearer", s.userInfo(userInfoRequest{authorization: "Bearer unbound-without-dpop"}))
	require.Zero(t, s.registry.registers.Load())
}
