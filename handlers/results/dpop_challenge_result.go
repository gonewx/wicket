// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gonewx/wicket"
)

// expiredTokenDescription is the error description replacing the
// expired_token error, which is not a protected resource error code.
const expiredTokenDescription = "The access token expired"

// DPoPChallengeResult answers a protected resource request with a DPoP
// authentication challenge (RFC 9449 section 7.1): a single
// WWW-Authenticate field
//
//	DPoP error="<code>"[, error_description="<text>"], algs="<algorithms>"
//
// and no body.
type DPoPChallengeResult struct {
	Error            error
	ErrorDescription string
	// Algorithms lists the accepted proof signature algorithms, sent space
	// separated in the algs parameter; the parameter is left out when it
	// is empty.
	Algorithms []string
}

// NewDPoPChallengeResult returns the challenge for err. A nil err stands for
// invalid_token.
func NewDPoPChallengeResult(err error, description string, algorithms []string) *DPoPChallengeResult {
	return &DPoPChallengeResult{Error: err, ErrorDescription: description, Algorithms: algorithms}
}

// Execute writes the challenge. invalid_dpop_proof answers 401; any other
// error takes its status from wicket.ProtectedResourceErrorStatusCodes, and
// 401 when it is not listed. expired_token is sent as invalid_token with the
// description "The access token expired".
func (r *DPoPChallengeResult) Execute(w http.ResponseWriter, _ *http.Request) error {
	code := r.Error
	description := r.ErrorDescription
	if code == nil {
		code = wicket.ProtectedResourceErrorsInvalidToken
	}
	if errors.Is(code, wicket.ProtectedResourceErrorsExpiredToken) {
		code = wicket.ProtectedResourceErrorsInvalidToken
		description = expiredTokenDescription
	}

	status := http.StatusUnauthorized
	if !errors.Is(code, wicket.TokenErrorsInvalidDPoPProof) {
		if listed, ok := wicket.ProtectedResourceErrorStatusCodes[code]; ok {
			status = listed
		}
	}

	var challenge strings.Builder
	challenge.WriteString(wicket.AuthenticationSchemesAuthorizationHeaderDPoP)
	challenge.WriteString(` error=`)
	challenge.WriteString(quotedString(code.Error()))
	if description != "" {
		challenge.WriteString(`, error_description=`)
		challenge.WriteString(quotedString(description))
	}
	if len(r.Algorithms) > 0 {
		challenge.WriteString(`, algs=`)
		challenge.WriteString(quotedString(strings.Join(r.Algorithms, " ")))
	}

	w.Header().Set("WWW-Authenticate", challenge.String())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	return nil
}

// quotedString renders value as an HTTP quoted-string, escaping the quote
// and backslash characters and dropping control characters.
func quotedString(value string) string {
	var quoted strings.Builder
	quoted.WriteByte('"')
	for _, c := range value {
		switch {
		case c == '"' || c == '\\':
			quoted.WriteByte('\\')
			quoted.WriteRune(c)
		case c < 0x20 || c == 0x7f:
		default:
			quoted.WriteRune(c)
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}
