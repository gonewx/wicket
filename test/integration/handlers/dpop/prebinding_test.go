// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

// boundCode runs the authorize endpoint for secretClientId with dpop_jkt
// and returns the issued code.
func (s *scene) boundCode(thumbprint string) string {
	s.t.Helper()
	authorization := s.authorize(secretClientId, url.Values{wicket.AuthorizeRequestDPoPJkt: {thumbprint}})
	require.NotNil(s.t, authorization)
	require.NotEmptyf(s.t, authorization.Code(), "error %q", authorization.Error())
	return authorization.Code()
}

// push pushes the authorization parameters of secretClientId with extra to
// the pushed authorization request endpoint, with header.
func (s *scene) push(extra url.Values, header http.Header) reply {
	s.t.Helper()
	values := url.Values{
		wicket.AuthorizeRequestResponseType: {wicket.ResponseTypesCode},
		wicket.AuthorizeRequestScope:        {wicket.StandardScopesOpenId + " " + scopeName},
		wicket.AuthorizeRequestRedirectUri:  {redirectUri},
		wicket.AuthorizeRequestState:        {"state"},
		wicket.AuthorizeRequestNonce:        {"nonce"},
	}
	for name, list := range extra {
		values[name] = list
	}
	request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+"/"+wicket.ProtocolRoutePathsPushedAuthorization, strings.NewReader(values.Encode()))
	require.NoError(s.t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, list := range header {
		for _, value := range list {
			request.Header.Add(name, value)
		}
	}
	request.SetBasicAuth(url.QueryEscape(secretClientId), url.QueryEscape(sharedSecret))
	return s.do(request)
}

// pushedCode pushes dpop_jkt and returns the code the authorize endpoint
// issues for the request_uri.
func (s *scene) pushedCode(thumbprint string, header http.Header) string {
	s.t.Helper()
	pushed := s.push(url.Values{wicket.AuthorizeRequestDPoPJkt: {thumbprint}}, header)
	require.Equalf(s.t, http.StatusCreated, pushed.status, "push: %s", pushed.body)
	requestUri := pushed.field("request_uri")
	require.NotEmpty(s.t, requestUri)
	require.NoError(s.t, s.pipeline.Login(subjectId))
	entry := s.pipeline.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
		ClientId: secretClientId,
		Extra:    url.Values{wicket.AuthorizeRequestRequestUri: {requestUri}},
	})
	require.NotNil(s.t, entry)
	require.NotEmptyf(s.t, entry.Code(), "error %q", entry.Error())
	return entry.Code()
}

func TestDPoPKeyThumbprintBindsTheAuthorizationCode(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	other := newProofKey(t)

	t.Run("matching key", func(t *testing.T) {
		code := s.boundCode(key.thumbprint())
		r := s.token(codeRequest(secretClientId, code), s.proof(key, proofSpec{}))
		cnf := s.requireIssued("matching key", r, false)
		require.Equal(t, map[string]any{"jkt": key.thumbprint()}, cnf)
	})
	t.Run("other key burns the code", func(t *testing.T) {
		code := s.boundCode(key.thumbprint())
		requireError(t, "other key", s.token(codeRequest(secretClientId, code), s.proof(other, proofSpec{})), "invalid_grant")
		requireError(t, "retry with the bound key", s.token(codeRequest(secretClientId, code), s.proof(key, proofSpec{})), "invalid_grant")
	})
	t.Run("no proof", func(t *testing.T) {
		code := s.boundCode(key.thumbprint())
		requireError(t, "no proof", s.token(codeRequest(secretClientId, code)), "invalid_grant")
	})
	t.Run("unbound code redeems as before", func(t *testing.T) {
		code := s.authorizationCode(secretClientId)
		require.Nil(t, s.requireIssued("unbound", s.token(codeRequest(secretClientId, code)), false))
	})
	t.Run("malformed dpop_jkt", func(t *testing.T) {
		for name, value := range map[string]string{
			"short":  key.thumbprint()[:42],
			"padded": key.thumbprint() + "=",
			"hex":    strings.Repeat("a", 64),
		} {
			s.pipeline.ErrorWasCalled = false
			s.pipeline.ErrorMessage = nil
			authorization := s.authorize(secretClientId, url.Values{wicket.AuthorizeRequestDPoPJkt: {value}})
			require.Nilf(t, authorization, "%s: code delivered to the client", name)
			require.Truef(t, s.pipeline.ErrorWasCalled, "%s: error page not shown", name)
			require.NotNilf(t, s.pipeline.ErrorMessage, "%s", name)
			require.Equalf(t, "invalid_request", s.pipeline.ErrorMessage.Error, "%s", name)
			require.Equalf(t, "Invalid dpop_jkt", s.pipeline.ErrorMessage.ErrorDescription, "%s", name)
		}
	})
}

func TestDPoPKeyThumbprintIgnoredWhileDPoPIsNotEnabled(t *testing.T) {
	s := newScene(t, sceneOptions{})
	for _, value := range []string{newProofKey(t).thumbprint(), "anything"} {
		code := s.boundCode(value)
		require.Nil(t, s.requireIssued(value, s.token(codeRequest(secretClientId, code)), false))
	}
}

func TestDPoPKeyThumbprintThroughPushedAuthorization(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true, pushedAuthorization: true})
	key := newProofKey(t)
	other := newProofKey(t)

	t.Run("matching key", func(t *testing.T) {
		code := s.pushedCode(key.thumbprint(), nil)
		cnf := s.requireIssued("pushed match", s.token(codeRequest(secretClientId, code), s.proof(key, proofSpec{})), false)
		require.Equal(t, map[string]any{"jkt": key.thumbprint()}, cnf)
	})
	t.Run("other key", func(t *testing.T) {
		code := s.pushedCode(key.thumbprint(), nil)
		requireError(t, "pushed other key", s.token(codeRequest(secretClientId, code), s.proof(other, proofSpec{})), "invalid_grant")
	})
	t.Run("no proof", func(t *testing.T) {
		code := s.pushedCode(key.thumbprint(), nil)
		requireError(t, "pushed no proof", s.token(codeRequest(secretClientId, code)), "invalid_grant")
	})
	t.Run("malformed dpop_jkt refused when pushed", func(t *testing.T) {
		r := s.push(url.Values{wicket.AuthorizeRequestDPoPJkt: {"not-a-thumbprint"}}, nil)
		require.Equalf(t, http.StatusBadRequest, r.status, "body %s", r.body)
		require.Equal(t, "invalid_request", r.field("error"))
		require.Equal(t, "Invalid dpop_jkt", r.field("error_description"))
	})
	t.Run("a DPoP header on the push is ignored", func(t *testing.T) {
		header := http.Header{wicket.DPoPHeaderName: {s.proof(other, proofSpec{}), "not a proof"}}
		code := s.pushedCode(key.thumbprint(), header)
		cnf := s.requireIssued("header ignored", s.token(codeRequest(secretClientId, code), s.proof(key, proofSpec{})), false)
		require.Equal(t, map[string]any{"jkt": key.thumbprint()}, cnf)
	})
}
