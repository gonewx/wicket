// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
)

// TestTokenRequestValidationProofKey verifies proof key verification during
// the authorization code exchange: challenge/verifier presence rules and the
// plain and S256 comparison methods, for clients that enforce a proof key
// and clients whose code simply carries one.
func TestTokenRequestValidationProofKey(t *testing.T) {
	t.Parallel()

	verifier := grantTestCodeVerifier

	tests := map[string]struct {
		clientId        string
		challenge       string
		challengeMethod string
		codeVerifier    string
		wantErr         error
	}{
		"plain method with matching verifier succeeds for enforcing client": {
			clientId:        "codeclient.pkce",
			challenge:       grantTestPlainChallenge(verifier),
			challengeMethod: gois.CodeChallengeMethodsPlain,
			codeVerifier:    verifier,
		},
		"plain method with matching verifier succeeds for non-enforcing client": {
			clientId:        "codeclient",
			challenge:       grantTestPlainChallenge(verifier),
			challengeMethod: gois.CodeChallengeMethodsPlain,
			codeVerifier:    verifier,
		},
		"plain method with matching verifier succeeds for hybrid client": {
			clientId:        "hybridclient.pkce",
			challenge:       grantTestPlainChallenge(verifier),
			challengeMethod: gois.CodeChallengeMethodsPlain,
			codeVerifier:    verifier,
		},
		"S256 method with matching verifier succeeds for enforcing client": {
			clientId:        "codeclient.pkce",
			challenge:       grantTestS256Challenge(verifier),
			challengeMethod: gois.CodeChallengeMethodsSha256,
			codeVerifier:    verifier,
		},
		"S256 method with matching verifier succeeds for non-enforcing client": {
			clientId:        "codeclient",
			challenge:       grantTestS256Challenge(verifier),
			challengeMethod: gois.CodeChallengeMethodsSha256,
			codeVerifier:    verifier,
		},
		"missing challenge and verifier is rejected for enforcing client": {
			clientId: "codeclient.pkce",
			wantErr:  gois.TokenErrorsInvalidGrant,
		},
		"verifier without stored challenge is rejected for enforcing client": {
			clientId:     "codeclient.pkce",
			codeVerifier: verifier,
			wantErr:      gois.TokenErrorsInvalidGrant,
		},
		"verifier without stored challenge is rejected for non-enforcing client": {
			clientId:     "codeclient",
			codeVerifier: verifier,
			wantErr:      gois.TokenErrorsInvalidGrant,
		},
		"plain method with mismatching verifier is rejected for enforcing client": {
			clientId:        "codeclient.pkce",
			challenge:       grantTestPlainChallenge(verifier),
			challengeMethod: gois.CodeChallengeMethodsPlain,
			codeVerifier:    verifier + "-mismatch",
			wantErr:         gois.TokenErrorsInvalidGrant,
		},
		"plain method with mismatching verifier is rejected for non-enforcing client": {
			clientId:        "codeclient",
			challenge:       grantTestPlainChallenge(verifier),
			challengeMethod: gois.CodeChallengeMethodsPlain,
			codeVerifier:    verifier + "-mismatch",
			wantErr:         gois.TokenErrorsInvalidGrant,
		},
		"S256 method rejects a value other than the original verifier for enforcing client": {
			clientId:        "codeclient.pkce",
			challenge:       grantTestS256Challenge(verifier),
			challengeMethod: gois.CodeChallengeMethodsSha256,
			codeVerifier:    grantTestPlainChallenge(verifier),
			wantErr:         gois.TokenErrorsInvalidGrant,
		},
		"S256 method rejects a value other than the original verifier for non-enforcing client": {
			clientId:        "codeclient",
			challenge:       grantTestS256Challenge(verifier),
			challengeMethod: gois.CodeChallengeMethodsSha256,
			codeVerifier:    grantTestPlainChallenge(verifier),
			wantErr:         gois.TokenErrorsInvalidGrant,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t)
			code := newGrantTestAuthorizationCode(tt.clientId, f.now)
			code.CodeChallenge = tt.challenge
			code.CodeChallengeMethod = tt.challengeMethod
			handle := storeGrantTestAuthorizationCode(t, f, code)

			parameters := url.Values{
				gois.TokenRequestGrantType:   {gois.GrantTypeAuthorizationCode},
				gois.TokenRequestCode:        {handle},
				gois.TokenRequestRedirectUri: {code.RedirectUri},
			}
			if tt.codeVerifier != "" {
				parameters.Set(gois.TokenRequestCodeVerifier, tt.codeVerifier)
			}

			result, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, tt.clientId))
			if tt.wantErr == nil {
				if result.Error != nil {
					t.Fatalf("unexpected error: %v (description %q)", result.Error, result.Description)
				}
				return
			}
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
		})
	}
}
