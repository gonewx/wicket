// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/services"
)

// userInfoDPoP holds what the userinfo endpoint needs to accept DPoP bound
// access tokens.
type userInfoDPoP struct {
	verifier *dpop.Verifier
	registry replay.Registry
	options  dpop.Options
	clock    services.SystemClock
	// algorithms is what the algs parameter of a challenge lists.
	algorithms []string
}

// SetDPoP makes the userinfo endpoint accept access tokens presented with
// the DPoP authorization scheme (RFC 9449 section 7). Such a request has to
// carry a proof for the request whose ath matches the token and whose key
// is the one the token's cnf.jkt names; the registry then records the proof
// identifier. Every rejection on that path, and the rejection of a DPoP
// bound token presented as a bearer token, is answered with a DPoP
// challenge. Without it the handler never reads the DPoP scheme or header.
func (h *UserInfoHandler) SetDPoP(verifier *dpop.Verifier, registry replay.Registry, options dpop.Options, clock services.SystemClock) {
	algorithms := slices.Clone(options.SigningAlgorithms)
	if len(algorithms) == 0 {
		algorithms = dpop.DefaultOptions().SigningAlgorithms
	}
	h.dpop = &userInfoDPoP{verifier: verifier, registry: registry, options: options, clock: clock, algorithms: algorithms}
}

// dpopAuthorization reads a DPoP scheme Authorization header. found reports
// that the header names the DPoP scheme, matched without regard to case;
// malformed reports that it is not followed by one or more spaces and a
// token free of whitespace.
func dpopAuthorization(r *http.Request) (token string, found bool, malformed bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, rest, _ := strings.Cut(header, " ")
	if !strings.EqualFold(scheme, wicket.AuthenticationSchemesAuthorizationHeaderDPoP) {
		return "", false, false
	}
	token = strings.TrimLeft(rest, " ")
	if token == "" || strings.ContainsFunc(token, isHeaderWhitespace) {
		return "", true, true
	}
	return token, true, false
}

func isHeaderWhitespace(c rune) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

// carriesFormAccessToken reports whether a form body also presents an access
// token, which a request using the Authorization header must not do
// (RFC 6750 section 2). A body that cannot be read counts as presenting one.
func carriesFormAccessToken(r *http.Request) bool {
	if !extensions.HasApplicationFormContentType(r) {
		return false
	}
	if err := r.ParseForm(); err != nil {
		return true
	}
	return r.PostForm.Has(wicket.AuthenticationSchemesFormPostBearer)
}

// processDPoP serves a request presenting its access token with the DPoP
// scheme. The stages run in order: the stateless proof checks (ath
// included), token validation, the cnf.jkt match, the certificate binding,
// and only then the registration of the proof identifier.
func (h *UserInfoHandler) processDPoP(w http.ResponseWriter, r *http.Request, token string, malformed bool) error {
	d := h.dpop
	if malformed || carriesFormAccessToken(r) {
		return d.challenge(w, r, wicket.ProtectedResourceErrorsInvalidRequest, "")
	}

	proof, err := d.verifier.VerifyForResource(r.Header.Values(wicket.DPoPHeaderName), r.Method, requestEndpointUri(r), token, d.clock.Now())
	if err != nil {
		h.logDPoPRejection(err.Error())
		return d.challenge(w, r, wicket.TokenErrorsInvalidDPoPProof, "")
	}

	validationResult, err := h.requestValidator.ValidateRequest(r.Context(), token)
	if err != nil {
		return fmt.Errorf("validate userinfo request: %w", err)
	}
	if validationResult.Error != nil {
		return d.challenge(w, r, validationResult.Error, validationResult.Description)
	}
	if validationResult.TokenValidationResult == nil {
		h.logDPoPRejection("no token claims")
		return d.challenge(w, r, wicket.ProtectedResourceErrorsInvalidToken, "")
	}
	tokenClaims := validationResult.TokenValidationResult.Claims
	thumbprint, bound, err := boundThumbprint(tokenClaims)
	if err != nil || !bound {
		h.logDPoPRejection("token not bound to a proof key")
		return d.challenge(w, r, wicket.ProtectedResourceErrorsInvalidToken, "")
	}
	if !dpop.ThumbprintMatches(proof, thumbprint) {
		h.logDPoPRejection("proof key does not match the token")
		return d.challenge(w, r, wicket.ProtectedResourceErrorsInvalidToken, "")
	}
	if err := h.checkCertificateBinding(r, tokenClaims); err != nil {
		return d.challenge(w, r, wicket.ProtectedResourceErrorsInvalidToken, "")
	}

	err = dpop.Register(r.Context(), d.registry, proof, d.options, d.clock.Now())
	switch {
	case err == nil:
	case errors.Is(err, dpop.ErrReplayedProof):
		h.logDPoPRejection("replay")
		return d.challenge(w, r, wicket.TokenErrorsInvalidDPoPProof, "")
	default:
		// The text of the underlying error may carry the registry key, so
		// only its type is recorded.
		if h.logger != nil {
			h.logger.Error("DPoP proof could not be registered",
				slog.String("error_type", fmt.Sprintf("%T", registrationCause(err))))
		}
		writeClientAuthenticationUnavailable(w)
		return nil
	}

	claims, err := h.generator.Handle(r.Context(), validationResult)
	if err != nil {
		return fmt.Errorf("generate userinfo response: %w", err)
	}
	return results.NewUserInfoResult(claims).Execute(w, r)
}

// rejectBoundBearer refuses a token bound to a DPoP proof key, or one whose
// confirmation cannot be read, presented as a bearer token (RFC 9449
// section 7.2). It reports whether a response was written. While DPoP is
// enabled the refusal is a DPoP challenge, otherwise a bearer one.
func (h *UserInfoHandler) rejectBoundBearer(w http.ResponseWriter, r *http.Request, tokenClaims []*claims.Claim) (written bool, err error) {
	_, bound, err := boundThumbprint(tokenClaims)
	if err == nil && !bound {
		return false, nil
	}
	if h.dpop != nil {
		h.logDPoPRejection("bearer token bound to a proof key or with a malformed confirmation")
		return true, h.dpop.challenge(w, r, wicket.ProtectedResourceErrorsInvalidToken, "")
	}
	return true, results.NewProtectedResourceErrorResult(wicket.ProtectedResourceErrorsInvalidToken, "").Execute(w, r)
}

// boundThumbprint returns the proof key thumbprint the cnf claim of a token
// binds it to. A token without a cnf claim, or whose cnf has no jkt, is not
// bound; a malformed cnf, or more than one cnf claim, is an error.
func boundThumbprint(tokenClaims []*claims.Claim) (thumbprint string, bound bool, err error) {
	var cnf []any
	for _, claim := range tokenClaims {
		if claim != nil && claim.Type == wicket.JwtClaimTypesConfirmation {
			cnf = append(cnf, claim.Value)
		}
	}
	switch len(cnf) {
	case 0:
		return "", false, nil
	case 1:
		if cnf[0] == nil {
			// A cnf claim that is present but null is not a confirmation.
			return "", false, dpop.ErrMalformedConfirmation
		}
		return dpop.ConfirmationThumbprint(cnf[0])
	default:
		return "", false, errMultipleConfirmations
	}
}

func (d *userInfoDPoP) challenge(w http.ResponseWriter, r *http.Request, code error, description string) error {
	return results.NewDPoPChallengeResult(code, description, d.algorithms).Execute(w, r)
}

// logDPoPRejection records why a DPoP request was refused. Neither the
// token nor the proof is part of the record.
func (h *UserInfoHandler) logDPoPRejection(reason string) {
	if h.logger != nil {
		h.logger.Warn("userinfo DPoP request rejected", slog.String("reason", reason))
	}
}
