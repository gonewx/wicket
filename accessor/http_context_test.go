// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package accessor

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultHttpContextAccessorIdentity(t *testing.T) {
	t.Parallel()

	t.Run("request is stored and read back as the same instance", func(t *testing.T) {
		t.Parallel()

		accessor := NewDefaultHttpContextAccessor()
		request := httptest.NewRequest(http.MethodGet, "/resource", nil)

		accessor.SetRequest(request)

		require.Same(t, request, accessor.Request())
	})

	t.Run("response writer is stored and read back as the same instance", func(t *testing.T) {
		t.Parallel()

		accessor := NewDefaultHttpContextAccessor()
		writer := httptest.NewRecorder()

		accessor.SetResponseWriter(writer)

		require.Same(t, writer, accessor.ResponseWriter())
	})
}
