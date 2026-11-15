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

// dpopNonceRequiredDescription is the error description answering a proof
// without an accepted server nonce.
const dpopNonceRequiredDescription = "DPoP proof must carry the server nonce"

// nonceSurfacePrefix precedes the issuer in the surface server nonces of
// the authorization server are issued for.
const nonceSurfacePrefix = "authorization-server "

// tokenDPoP holds what the token endpoint needs to accept DPoP proofs.
type tokenDPoP struct {
	verifier *dpop.Verifier
	registry replay.Registry
	options  dpop.Options
	clock    services.SystemClock

	// nonces is set by SetDPoPNonces; nil leaves server nonces off.
	nonces *dpop.NonceSealer
	// surface names the side the nonces of a request are issued for.
	surface func(*http.Request) (string, bool)
}

// SetDPoP makes the token endpoint accept DPoP proofs (RFC 9449). Without
// it the handler never reads the DPoP header. The registry records proof
// identifiers; it is only called for a proof that passed every stateless
// check and whose client authenticated.
func (h *TokenHandler) SetDPoP(verifier *dpop.Verifier, registry replay.Registry, options dpop.Options, clock services.SystemClock) {
	h.dpop = &tokenDPoP{verifier: verifier, registry: registry, options: options, clock: clock, surface: authorizationServerNonceSurface}
}

// SetDPoPNonces makes the token endpoint demand a server nonce (RFC 9449
// section 8) in every DPoP proof, issued and checked by sealer. Every
// response to a request carrying a DPoP header then carries a fresh nonce
// in the DPoP-Nonce header. It must follow SetDPoP.
func (h *TokenHandler) SetDPoPNonces(sealer *dpop.NonceSealer) {
	if h.dpop == nil {
		panic("SetDPoPNonces requires SetDPoP")
	}
	h.dpop.nonces = sealer
}

// authorizationServerNonceSurface names the surface the nonces of r are
// issued for: the issuer. The main route and its mutual TLS alias accept
// each other's nonces only while they share the issuer, that is when
// IssuerUri is configured or the alias is served on the same origin; an
// alias on its own host (MutualTls.DomainName) without IssuerUri has its
// own issuer and issues its own nonces, so a client is challenged once per
// host. It reports false when the issuer cannot be
// determined; there is no fallback.
func authorizationServerNonceSurface(r *http.Request) (string, bool) {
	scope := hosting.ScopeFrom(r.Context())
	if scope == nil {
		return "", false
	}
	issuers, ok := godi.Get[services.IssuerNameService](scope)
	if !ok || issuers == nil {
		return "", false
	}
	issuer := issuers.GetCurrent()
	if issuer == "" {
		return "", false
	}
	return nonceSurfacePrefix + issuer, true
}

// dpopStatelessStages runs the DPoP stages that change no state, in order:
// a fresh server nonce is issued into the response header, the proof is
// verified, and its server nonce is checked. It returns the accepted proof,
// or nil when r carries none. written reports that a response was already
// written.
func (h *TokenHandler) dpopStatelessStages(w http.ResponseWriter, r *http.Request) (proof *dpop.Proof, written bool, err error) {
	d := h.dpop
	nonces := d.nonces != nil && len(r.Header.Values(wicket.DPoPHeaderName)) > 0
	var surface string
	if nonces {
		var ok bool
		if surface, ok = d.surface(r); !ok {
			h.logNonceUnavailable(errors.New("issuer unavailable"))
			writeClientAuthenticationUnavailable(w)
			return nil, true, nil
		}
		nonce, err := d.nonces.Issue(surface, d.clock.Now())
		if err != nil {
			h.logNonceUnavailable(err)
			writeClientAuthenticationUnavailable(w)
			return nil, true, nil
		}
		w.Header().Set(wicket.DPoPNonceHeaderName, nonce)
	}

	proof, err = d.verifyProof(r)
	if err != nil {
		h.logProofRejection(err.Error())
		return nil, true, writeInvalidDPoPProof(w, r)
	}
	if proof == nil || !nonces {
		return proof, false, nil
	}

	if proof.Nonce == "" {
		h.logProofRejection("nonce missing")
		return nil, true, writeUseDPoPNonce(w, r)
	}
	deadline, err := d.nonces.Check(proof.Nonce, surface, d.clock.Now())
	switch {
	case err == nil:
		proof.NonceDeadline = deadline
		return proof, false, nil
	case errors.Is(err, dpop.ErrInvalidNonce):
		h.logProofRejection(err.Error())
		return nil, true, writeUseDPoPNonce(w, r)
	default:
		h.logNonceUnavailable(err)
		w.Header().Del(wicket.DPoPNonceHeaderName)
		writeClientAuthenticationUnavailable(w)
		return nil, true, nil
	}
}

// writeUseDPoPNonce answers a proof without an accepted server nonce. The
// fresh nonce is already in the response header.
func writeUseDPoPNonce(w http.ResponseWriter, r *http.Request) error {
	response := responses_models.NewTokenErrorResponse()
	response.Error = wicket.TokenErrorsUseDPoPNonce
	response.ErrorDescription = dpopNonceRequiredDescription
	return results.NewTokenErrorResult(response).Execute(w, r)
}

// logNonceUnavailable records that server nonces could not be issued or
// checked. The key source error may carry anything, so only the type of
// the innermost cause is recorded.
func (h *TokenHandler) logNonceUnavailable(err error) {
	if h.logger == nil {
		return
	}
	cause := err
	for next := errors.Unwrap(cause); next != nil; next = errors.Unwrap(cause) {
		cause = next
	}
	h.logger.Error("DPoP server nonce unavailable", slog.String("error_type", fmt.Sprintf("%T", cause)))
}

// verifyProof runs the stateless checks of the DPoP proof of r. It returns
// the accepted proof, or nil when r carries none.
func (d *tokenDPoP) verifyProof(r *http.Request) (*dpop.Proof, error) {
	values := r.Header.Values(wicket.DPoPHeaderName)
	if len(values) == 0 {
		return nil, nil
	}
	proof, err := d.verifier.Verify(values, r.Method, requestEndpointUri(r), d.clock.Now())
	if err != nil {
		return nil, err
	}
	return &proof, nil
}

// requestEndpointUri is the URI the proof's htu claim has to name: the base
// URL of the request followed by the path it was addressed to, so the main
// route and its mutual TLS alias each stand for themselves.
func requestEndpointUri(r *http.Request) string {
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
