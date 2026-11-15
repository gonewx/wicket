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
	// Nonce, when not empty, is sent in the DPoP-Nonce header as the
	// server nonce the next proof has to carry (RFC 9449 section 8).
	Nonce string
	// withoutError leaves the error and error_description parameters out,
	// for a request that presented no access token (RFC 6750 section 3.1).
	withoutError bool
}

// NewDPoPChallengeResult returns the challenge for err. A nil err stands for
// invalid_token.
func NewDPoPChallengeResult(err error, description string, algorithms []string) *DPoPChallengeResult {
	return &DPoPChallengeResult{Error: err, ErrorDescription: description, Algorithms: algorithms}
}

// NewDPoPAlgorithmsChallengeResult returns the 401 challenge answering a
// request that presented no access token: a single WWW-Authenticate field
//
//	DPoP algs="<algorithms>"
//
// carrying no error parameter; the algs parameter is left out when
// algorithms is empty.
func NewDPoPAlgorithmsChallengeResult(algorithms []string) *DPoPChallengeResult {
	return &DPoPChallengeResult{Algorithms: algorithms, withoutError: true}
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

	var parameters []string
	if r.withoutError {
		status = http.StatusUnauthorized
	} else {
		parameters = append(parameters, `error=`+quotedString(code.Error()))
		if description != "" {
			parameters = append(parameters, `error_description=`+quotedString(description))
		}
	}
	if len(r.Algorithms) > 0 {
		parameters = append(parameters, `algs=`+quotedString(strings.Join(r.Algorithms, " ")))
	}
	challenge := wicket.AuthenticationSchemesAuthorizationHeaderDPoP
	if len(parameters) > 0 {
		challenge += " " + strings.Join(parameters, ", ")
	}

	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Cache-Control", "no-store")
	if r.Nonce != "" {
		w.Header().Set(wicket.DPoPNonceHeaderName, r.Nonce)
	}
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
