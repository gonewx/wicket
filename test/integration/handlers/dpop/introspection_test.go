// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

func TestIntrospectionReturnsTheProofKeyConfirmation(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	want := map[string]any{"jkt": key.thumbprint()}

	t.Run("bound JWT", func(t *testing.T) {
		introspection := s.introspect(s.issue(secretClientId, &key))
		require.Equal(t, true, introspection["active"])
		require.Equal(t, want, introspection["cnf"])
	})
	t.Run("bound reference token", func(t *testing.T) {
		introspection := s.introspect(s.issue(referenceClientId, &key))
		require.Equal(t, true, introspection["active"])
		require.Equal(t, want, introspection["cnf"])
	})
	t.Run("stored reference token", func(t *testing.T) {
		s.storeUserInfoReference("introspected-bound", time.Now(), map[string]any{"jkt": key.thumbprint()})
		introspection := s.introspect("introspected-bound")
		require.Equal(t, true, introspection["active"])
		require.Equal(t, want, introspection["cnf"])
	})
	t.Run("unbound JWT", func(t *testing.T) {
		introspection := s.introspect(s.issue(secretClientId, nil))
		require.Equal(t, true, introspection["active"])
		require.NotContains(t, introspection, "cnf")
	})
	t.Run("unbound reference token", func(t *testing.T) {
		introspection := s.introspect(s.issue(referenceClientId, nil))
		require.Equal(t, true, introspection["active"])
		require.NotContains(t, introspection, "cnf")
	})
	t.Run("token_type is not reported", func(t *testing.T) {
		r := s.token(passwordRequest(secretClientId), s.proof(key, proofSpec{}))
		require.Equal(t, http.StatusOK, r.status, r.body)
		introspection := s.introspect(r.field("access_token"))
		require.NotContains(t, introspection, "token_type")
	})
}

func TestSignedIntrospectionReturnsTheProofKeyConfirmation(t *testing.T) {
	s := newScene(t, sceneOptions{enable: true})
	key := newProofKey(t)
	token := s.issue(secretClientId, &key)

	request, err := http.NewRequest(http.MethodPost, s.pipeline.TestServer.URL+integration_common.IntrospectionEndpoint,
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	require.NoError(t, err)
	request.SetBasicAuth(apiName, sharedSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", wicket.MediaTypesTokenIntrospectionJwt)
	r := s.do(request)
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.Equal(t, wicket.MediaTypesTokenIntrospectionJwt, r.header.Get("Content-Type"))

	message, err := jws.Parse([]byte(r.body))
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(message.Payload(), &payload))
	introspection, ok := payload[wicket.ClaimTypesTokenIntrospection].(map[string]any)
	require.True(t, ok, "token_introspection: %v", payload)
	require.Equal(t, true, introspection["active"])
	require.Equal(t, map[string]any{"jkt": key.thumbprint()}, introspection["cnf"])
}
