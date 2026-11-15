// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt

import (
	"errors"
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/handlers/results"
)

// dpopNonceRequiredDescription is the error description of a use_dpop_nonce
// challenge.
const dpopNonceRequiredDescription = "DPoP proof must carry the server nonce"

// HandleChallenge answers a challenge. With Options.DPoP unset it is the
// default bare 401. With it set, the challenge follows the authentication
// result of the request (RFC 9449 section 7.1): no presented token yields
// 401 DPoP algs="…"; a rejected proof 401 invalid_dpop_proof; a missing or
// refused server nonce 401 use_dpop_nonce; a malformed DPoP authorization
// header 400 invalid_request; a proof that could not be judged a bare 500;
// any other failure 401 invalid_token. In the server nonce mode every 401
// carries a fresh nonce in DPoP-Nonce, and a nonce that cannot be issued
// turns the answer into the bare 500. The OnChallenge event is not raised
// while DPoP validation is on.
func (h *Handler) HandleChallenge(properties *auth.Properties) error {
	validation := h.Options.DPoP
	if validation == nil {
		return h.Handler.HandleChallenge(properties)
	}
	w := h.Response()

	result, err := h.Authenticate()
	var challenge *results.DPoPChallengeResult
	switch {
	case !validation.constructed:
		writeDPoPUnavailable(w)
		return nil
	case err != nil:
		// An event failed the authentication without a result.
		challenge = results.NewDPoPChallengeResult(wicket.ProtectedResourceErrorsInvalidToken, "", validation.algorithms)
	case result == nil || result.Failure == nil:
		challenge = results.NewDPoPAlgorithmsChallengeResult(validation.algorithms)
	case errors.Is(result.Failure, ErrDPoPUnavailable):
		writeDPoPUnavailable(w)
		return nil
	case errors.Is(result.Failure, ErrDPoPProofRejected):
		challenge = results.NewDPoPChallengeResult(wicket.TokenErrorsInvalidDPoPProof, "", validation.algorithms)
	case errors.Is(result.Failure, ErrDPoPNonceRequired):
		challenge = results.NewDPoPChallengeResult(wicket.TokenErrorsUseDPoPNonce, dpopNonceRequiredDescription, validation.algorithms)
	case errors.Is(result.Failure, ErrDPoPMalformedAuthorization):
		challenge = results.NewDPoPChallengeResult(wicket.ProtectedResourceErrorsInvalidRequest, "", validation.algorithms)
	default:
		challenge = results.NewDPoPChallengeResult(wicket.ProtectedResourceErrorsInvalidToken, "", validation.algorithms)
	}

	if validation.sealer != nil && !errors.Is(challenge.Error, wicket.ProtectedResourceErrorsInvalidRequest) {
		nonce, err := validation.sealer.Issue(validation.surface, h.dpopNow())
		if err != nil {
			h.logDPoPUnavailable("DPoP server nonce unavailable", err)
			writeDPoPUnavailable(w)
			return nil
		}
		challenge.Nonce = nonce
	}
	return challenge.Execute(w, h.Request())
}

// writeDPoPUnavailable answers a request whose DPoP proof could not be
// judged.
func writeDPoPUnavailable(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusInternalServerError)
}
