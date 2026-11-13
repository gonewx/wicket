// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"encoding/json"
	"net/http"

	"github.com/gonewx/wicket"
)

// ClientAuthenticationErrorResult answers a failed client authentication with
// the RFC 6749 §5.2 invalid_client error. With a challenge it writes 401 and
// the challenge as WWW-Authenticate, as required when the client tried to
// authenticate through the Authorization request header; without one it
// writes 400.
type ClientAuthenticationErrorResult struct {
	Challenge string
}

func NewClientAuthenticationErrorResult(challenge string) *ClientAuthenticationErrorResult {
	return &ClientAuthenticationErrorResult{Challenge: challenge}
}

func (r *ClientAuthenticationErrorResult) Execute(w http.ResponseWriter, _ *http.Request) error {
	status := http.StatusBadRequest
	if r.Challenge != "" {
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", r.Challenge)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	return json.NewEncoder(w).Encode(map[string]string{"error": wicket.TokenErrorsInvalidClient.Error()})
}
