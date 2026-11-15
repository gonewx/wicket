// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/replay"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

// dpopProofRequiredDescription is the error description answering a client
// that has to present a DPoP proof and presented none.
const dpopProofRequiredDescription = "DPoP proof required"

// tokenDPoP holds what the token endpoint needs to accept DPoP proofs.
type tokenDPoP struct {
	verifier *dpop.Verifier
	registry replay.Registry
	options  dpop.Options
	clock    services.SystemClock
}

// SetDPoP makes the token endpoint accept DPoP proofs (RFC 9449). Without
// it the handler never reads the DPoP header. The registry records proof
// identifiers; it is only called for a proof that passed every stateless
// check and whose client authenticated.
func (h *TokenHandler) SetDPoP(verifier *dpop.Verifier, registry replay.Registry, options dpop.Options, clock services.SystemClock) {
	h.dpop = &tokenDPoP{verifier: verifier, registry: registry, options: options, clock: clock}
}

// verifyProof runs the stateless checks of the DPoP proof of r. It returns
// the accepted proof, or nil when r carries none.
func (d *tokenDPoP) verifyProof(r *http.Request) (*dpop.Proof, error) {
	values := r.Header.Values(wicket.DPoPHeaderName)
	if len(values) == 0 {
		return nil, nil
	}
	proof, err := d.verifier.Verify(values, r.Method, tokenEndpointUri(r), d.clock.Now())
	if err != nil {
		return nil, err
	}
	return &proof, nil
}

// tokenEndpointUri is the URI the proof's htu claim has to name: the base URL
// of the request followed by the path it was addressed to, so the main route
// and its mutual TLS alias each stand for themselves.
func tokenEndpointUri(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if scope := hosting.ScopeFrom(r.Context()); scope != nil {
		if urls, ok := godi.Get[services.ServerUrls](scope); ok && urls != nil {
			return urls.BaseUrl() + path
		}
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return utils.EnsureTrailingSlash(scheme+"://"+r.Host) + path
}

// writeInvalidDPoPProof answers a request whose proof is invalid or was
// replayed.
func writeInvalidDPoPProof(w http.ResponseWriter, r *http.Request) error {
	response := responses_models.NewTokenErrorResponse()
	response.Error = wicket.TokenErrorsInvalidDPoPProof
	return results.NewTokenErrorResult(response).Execute(w, r)
}

// enforceAndRegister runs the DPoP stages that follow client authentication:
// a client that requires DPoP is refused without a proof, and the identifier
// of a presented proof is registered. written reports that a response was
// already written.
func (h *TokenHandler) enforceAndRegister(w http.ResponseWriter, r *http.Request, client *storage_models.Client, proof *dpop.Proof) (written bool, err error) {
	if proof == nil {
		if client != nil && client.RequireDPoP {
			response := responses_models.NewTokenErrorResponse()
			response.Error = wicket.TokenErrorsInvalidRequest
			response.ErrorDescription = dpopProofRequiredDescription
			return true, results.NewTokenErrorResult(response).Execute(w, r)
		}
		return false, nil
	}
	err = dpop.Register(r.Context(), h.dpop.registry, *proof, h.dpop.options, h.dpop.clock.Now())
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, dpop.ErrReplayedProof):
		h.logProofRejection("replay")
		return true, writeInvalidDPoPProof(w, r)
	default:
		// The text of the underlying error may carry the registry key, so
		// only its type is recorded.
		if h.logger != nil {
			h.logger.Error("DPoP proof could not be registered",
				slog.String("error_type", fmt.Sprintf("%T", registrationCause(err))))
		}
		writeClientAuthenticationUnavailable(w)
		return true, nil
	}
}

// registrationCause returns the registry failure a registration error wraps,
// or err itself when it wraps none.
func registrationCause(err error) error {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		if causes := joined.Unwrap(); len(causes) > 0 {
			return causes[len(causes)-1]
		}
	}
	return err
}

// logProofRejection records why a proof was refused. The proof and its
// identifier are never part of the record.
func (h *TokenHandler) logProofRejection(reason string) {
	if h.logger != nil {
		h.logger.Warn("DPoP proof rejected", slog.String("reason", reason))
	}
}
