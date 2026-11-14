// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import "net/http"

// clientAuthenticationUnavailableBody is the whole response body written
// when client authentication could not be decided.
const clientAuthenticationUnavailableBody = "Internal Server Error\n"

// writeClientAuthenticationUnavailable answers a request whose client
// authentication could not be decided because the replay registry failed.
// The response is fixed: it carries no protocol error and no detail of the
// failure, and must not be cached.
func writeClientAuthenticationUnavailable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(clientAuthenticationUnavailableBody))
}
