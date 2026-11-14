// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package certbound

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

func TestBoundIssuanceAtBothTokenEndpoints(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, mutualTls: true})
	request := url.Values{"grant_type": {wicket.GrantTypeClientCredentials}, "scope": {scopeName}, "client_id": {mtlsClientId}}

	for _, endpoint := range []string{integration_common.TokenEndpoint, "/" + wicket.ProtocolRoutePathsMtlsToken} {
		r := s.post(endpoint, request, s.mtlsCertificate)
		mustIssue(t, endpoint, r)
		requireBoundTo(t, jwtClaims(t, r.field("access_token")), s.mtlsCertificate)
	}

	// A client authenticated with its secret is bound to the certificate it
	// presents as well.
	r := s.post(integration_common.TokenEndpoint, passwordRequest(boundClientId), s.a)
	mustIssue(t, "secret client", r)
	requireBoundTo(t, jwtClaims(t, r.field("access_token")), s.a)
}

func TestUnregisteredClientIsNotBound(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, mutualTls: true})
	for name, certificates := range map[string][]*x509.Certificate{"with a certificate": {s.a}, "without one": nil} {
		r := s.post(integration_common.TokenEndpoint, passwordRequest(plainClientId), certificates...)
		mustIssue(t, name, r)
		_, bound := jwtClaims(t, r.field("access_token"))["cnf"]
		require.Falsef(t, bound, "%s: token carries cnf", name)
	}
}

func TestMissingCertificateIsRefusedBeforeAnyGrantIsRedeemed(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, mutualTls: true})

	mustBeInvalidClient(t, "password grant", s.post(integration_common.TokenEndpoint, passwordRequest(boundClientId)))
	mustBeInvalidClient(t, "mutual TLS client", s.post(integration_common.TokenEndpoint,
		url.Values{"grant_type": {wicket.GrantTypeClientCredentials}, "scope": {scopeName}, "client_id": {mtlsClientId}}))

	t.Run("refresh token", func(t *testing.T) {
		issued := s.post(integration_common.TokenEndpoint, passwordRequest(boundClientId), s.a)
		mustIssue(t, "password grant", issued)
		refresh := issued.field("refresh_token")
		require.NotEmpty(t, refresh)

		mustBeInvalidClient(t, "refresh without certificate", s.post(integration_common.TokenEndpoint, refreshRequest(boundClientId, refresh)))
		redeemed := s.post(integration_common.TokenEndpoint, refreshRequest(boundClientId, refresh), s.a)
		mustIssue(t, "refresh with certificate after the refusal", redeemed)
	})

	t.Run("authorization code", func(t *testing.T) {
		require.NoError(t, s.pipeline.Login(subjectId))
		authorization := s.pipeline.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
			ClientId:     boundClientId,
			ResponseType: "code",
			Scope:        wicket.StandardScopesOpenId + " " + scopeName,
			RedirectUri:  redirectUri,
			State:        "state",
			Nonce:        "nonce",
		})
		require.NotNil(t, authorization)
		require.NotEmpty(t, authorization.Code())
		request := url.Values{
			"grant_type":    {wicket.GrantTypeAuthorizationCode},
			"code":          {authorization.Code()},
			"redirect_uri":  {redirectUri},
			"client_id":     {boundClientId},
			"client_secret": {sharedSecret},
		}

		mustBeInvalidClient(t, "code without certificate", s.post(integration_common.TokenEndpoint, request))
		redeemed := s.post(integration_common.TokenEndpoint, request, s.b)
		mustIssue(t, "code with certificate after the refusal", redeemed)
		requireBoundTo(t, jwtClaims(t, redeemed.field("access_token")), s.b)
	})
}

func TestRefreshRebindsToTheCurrentCertificate(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, mutualTls: true})
	for _, clientId := range []string{boundClientId, boundUpdatingClientId} {
		t.Run(clientId, func(t *testing.T) {
			issued := s.post(integration_common.TokenEndpoint, passwordRequest(clientId), s.a)
			mustIssue(t, "password grant", issued)
			requireBoundTo(t, jwtClaims(t, issued.field("access_token")), s.a)

			refreshed := s.post(integration_common.TokenEndpoint, refreshRequest(clientId, issued.field("refresh_token")), s.b)
			mustIssue(t, "refresh", refreshed)
			requireBoundTo(t, jwtClaims(t, refreshed.field("access_token")), s.b)

			// The rebound token is accepted with the new certificate only.
			require.Equal(t, http.StatusOK, s.userInfo(refreshed.field("access_token"), s.b).status)
			require.Equal(t, http.StatusUnauthorized, s.userInfo(refreshed.field("access_token"), s.a).status)
		})
	}
}

func TestUserInfoChecksTheBinding(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, mutualTls: true})
	issued := s.post(integration_common.TokenEndpoint, passwordRequest(boundClientId), s.a)
	mustIssue(t, "bound", issued)
	token := issued.field("access_token")

	ok := s.userInfo(token, s.a)
	require.Equal(t, http.StatusOK, ok.status, "body %s", ok.body)
	document := ok.document(t)
	require.Equal(t, subjectId, document["sub"])
	_, carries := document["cnf"]
	require.False(t, carries, "userinfo response carries cnf: %s", ok.body)

	require.Equal(t, http.StatusUnauthorized, s.userInfo(token, s.b).status, "another certificate")
	require.Equal(t, http.StatusUnauthorized, s.userInfo(token).status, "no certificate")

	plain := s.post(integration_common.TokenEndpoint, passwordRequest(plainClientId))
	mustIssue(t, "unbound", plain)
	require.Equal(t, http.StatusOK, s.userInfo(plain.field("access_token")).status, "unbound token without certificate")
	require.Equal(t, http.StatusOK, s.userInfo(plain.field("access_token"), s.b).status, "unbound token with a certificate")
}

func TestMalformedConfirmationIsRefused(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, mutualTls: true})
	cnf := func(value any) *claimspkg.Claim {
		return claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesConfirmation), claimspkg.WithClaimValue(value))
	}
	cases := []struct {
		name  string
		extra []*claimspkg.Claim
	}{
		{"not an object", []*claimspkg.Claim{cnf("text")}},
		{"empty thumbprint", []*claimspkg.Claim{cnf(map[string]any{"x5t#S256": ""})}},
		{"numeric thumbprint", []*claimspkg.Claim{cnf(map[string]any{"x5t#S256": 7})}},
		{"two cnf claims", []*claimspkg.Claim{cnf(map[string]any{"x5t#S256": thumbprint(s.a)}), cnf(map[string]any{"x5t#S256": thumbprint(s.a)})}},
	}
	for i, tc := range cases {
		handle := "malformed-" + strconv.Itoa(i)
		s.storeReference(t, handle, plainClientId, "", tc.extra...)
		require.Equalf(t, http.StatusUnauthorized, s.userInfo(handle, s.a).status, "%s", tc.name)
	}

	// The same record with a well formed confirmation is accepted.
	s.storeReference(t, "well-formed", plainClientId, "", cnf(map[string]any{"x5t#S256": thumbprint(s.a)}))
	require.Equal(t, http.StatusOK, s.userInfo("well-formed", s.a).status)
}

func TestIntrospectionReturnsTheConfirmation(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, mutualTls: true})

	t.Run("bound JWT", func(t *testing.T) {
		issued := s.post(integration_common.TokenEndpoint, passwordRequest(boundClientId), s.a)
		mustIssue(t, "bound", issued)
		document := s.introspect(issued.field("access_token"))
		require.Equal(t, true, document["active"])
		requireBoundTo(t, document, s.a)
	})
	t.Run("bound reference token", func(t *testing.T) {
		issued := s.post(integration_common.TokenEndpoint, passwordRequest(referenceClientId), s.b)
		mustIssue(t, "bound reference", issued)
		handle := issued.field("access_token")
		require.NotContains(t, handle, ".")
		document := s.introspect(handle)
		require.Equal(t, true, document["active"])
		requireBoundTo(t, document, s.b)
		require.Equal(t, http.StatusOK, s.userInfo(handle, s.b).status)
		require.Equal(t, http.StatusUnauthorized, s.userInfo(handle, s.a).status)
	})
	t.Run("store fixture reference record", func(t *testing.T) {
		confirmation := `{"x5t#S256":"` + thumbprint(s.a) + `"}`
		s.storeReference(t, "fixture-bound", plainClientId, confirmation,
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesConfirmation), claimspkg.WithClaimValue(map[string]any{"x5t#S256": thumbprint(s.a)})))
		document := s.introspect("fixture-bound")
		require.Equal(t, true, document["active"])
		requireBoundTo(t, document, s.a)
	})
	t.Run("unbound JWT", func(t *testing.T) {
		issued := s.post(integration_common.TokenEndpoint, passwordRequest(plainClientId))
		mustIssue(t, "unbound", issued)
		document := s.introspect(issued.field("access_token"))
		require.Equal(t, true, document["active"])
		_, carries := document["cnf"]
		require.False(t, carries)
	})
}

func TestDiscoveryAdvertisesBoundTokens(t *testing.T) {
	cases := []struct {
		name      string
		options   sceneOptions
		advertise bool
	}{
		{"enabled and advertised", sceneOptions{enable: true, mutualTls: true}, true},
		{"enabled but mutual TLS not advertised", sceneOptions{enable: true}, false},
		{"not enabled", sceneOptions{mutualTls: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newScene(t, tc.options)
			value, ok := s.discovery()[wicket.DiscoveryTlsClientCertificateBoundAccessTokens]
			if tc.advertise {
				require.True(t, ok)
				require.Equal(t, true, value)
			} else {
				require.False(t, ok, "advertised as %v", value)
			}
		})
	}
}

func TestInvalidRegistrationsAreRefused(t *testing.T) {
	t.Run("feature not enabled", func(t *testing.T) {
		s := newScene(t, sceneOptions{})
		mustBeInvalidClient(t, "bound client", s.post(integration_common.TokenEndpoint, passwordRequest(boundClientId), s.a))
		// Unregistered clients behave as before.
		r := s.post(integration_common.TokenEndpoint, passwordRequest(plainClientId), s.a)
		mustIssue(t, "plain client", r)
		_, bound := jwtClaims(t, r.field("access_token"))["cnf"]
		require.False(t, bound)
	})
	t.Run("enabled", func(t *testing.T) {
		s := newScene(t, sceneOptions{enable: true, mutualTls: true})
		mustBeInvalidClient(t, "front channel tokens", s.post(integration_common.TokenEndpoint, passwordRequest(browserClientId), s.a))
		public := passwordRequest(publicClientId)
		public.Del("client_secret")
		mustBeInvalidClient(t, "public client", s.post(integration_common.TokenEndpoint, public, s.a))

		// The same registrations without the flag are valid.
		mustIssue(t, "front channel control", s.post(integration_common.TokenEndpoint, passwordRequest(browserControlClientId), s.a))
		control := passwordRequest(publicControlClientId)
		control.Del("client_secret")
		mustIssue(t, "public control", s.post(integration_common.TokenEndpoint, control, s.a))
	})
}
