// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
