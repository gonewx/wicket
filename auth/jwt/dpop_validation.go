// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/replay"
)

// resourceNonceSurfacePrefix precedes DPoPValidationConfig.Resource in the
// surface the server nonces of a protected resource are issued for, so a
// nonce of the authorization server is never accepted here and the other way
// round.
const resourceNonceSurfacePrefix = "resource-server "

var (
	// ErrInvalidDPoPConfiguration reports a DPoPValidationConfig that
	// NewDPoPValidation refuses.
	ErrInvalidDPoPConfiguration = errors.New("jwt: invalid DPoP validation configuration")

	// ErrDPoPProofRejected fails a request whose DPoP proof is missing,
	// invalid or replayed, or whose ath does not match the access token.
	ErrDPoPProofRejected = errors.New("jwt: DPoP proof rejected")
	// ErrDPoPNonceRequired fails a request whose DPoP proof carries no
	// server nonce, or one that is not accepted, while a nonce is required.
	ErrDPoPNonceRequired = errors.New("jwt: DPoP proof must carry the server nonce")
	// ErrDPoPTokenBinding fails a request whose access token does not fit
	// the scheme it is presented with: a token without cnf.jkt or one bound
	// to another key presented with the DPoP scheme, a bound token presented
	// as a bearer token, a malformed cnf, or a token whose claims cannot be
	// read.
	ErrDPoPTokenBinding = errors.New("jwt: access token does not fit its DPoP binding")
	// ErrDPoPMalformedAuthorization fails a request whose DPoP scheme
	// Authorization header lacks a token or holds whitespace in it.
	ErrDPoPMalformedAuthorization = errors.New("jwt: malformed DPoP authorization header")
	// ErrDPoPUnavailable fails a request whose DPoP proof could not be
	// judged: the replay registry or the nonce key source failed, or the
	// DPoPValidation was not made by NewDPoPValidation.
	ErrDPoPUnavailable = errors.New("jwt: DPoP validation unavailable")
)

// DPoPValidationConfig is what NewDPoPValidation builds a DPoPValidation
// from.
type DPoPValidationConfig struct {
	// Options configures proof verification; zero fields take the defaults
	// of dpop.DefaultOptions. RequireNonce selects the server nonce
	// freshness mode, otherwise freshness rests on iat alone.
	Options dpop.Options
	// Registry records the identifier of every accepted proof. It is
	// required; an in-memory registry has to be passed explicitly. The
	// host reclaims expired records with RemoveExpired.
	Registry replay.Registry
	// NonceKeys provides the keys of server nonces. It is required while
	// Options.RequireNonce is set and ignored otherwise.
	NonceKeys dpop.NonceKeySource
	// Resource names this protected resource in the surface its server
	// nonces are issued for. It is required while Options.RequireNonce is
	// set and ignored otherwise.
	Resource string
	// RequestUri, when set, returns the URI the htu claim of a proof has to
	// name, for deployments behind a reverse proxy. By default it is
	// scheme://Host/path of the request, the scheme being https when the
	// request arrived over TLS. It must return the absolute URI
	// (scheme://host/path) the client addressed; an empty or relative value
	// fails every proof as invalid_dpop_proof.
	RequestUri func(*http.Request) string
}

// DPoPValidation makes the JWT bearer handler accept access tokens presented
// with the DPoP authorization scheme (RFC 9449 section 7) once it is set on
// Options.DPoP. It is only usable when made by NewDPoPValidation; any other
// value fails every request.
type DPoPValidation struct {
	constructed bool
	verifier    *dpop.Verifier
	registry    replay.Registry
	options     dpop.Options
	// algorithms is what the algs parameter of a challenge lists.
	algorithms []string
	// sealer and surface are set in the server nonce freshness mode.
	sealer     *dpop.NonceSealer
	surface    string
	requestUri func(*http.Request) string
}

// NewDPoPValidation checks config and returns the DPoP validation it
// describes. It fails with an error matching ErrInvalidDPoPConfiguration
// when the options are invalid, the registry is missing, or, while a server
// nonce is required, the nonce key source is missing, fails or yields
// invalid keys, or the resource is empty.
func NewDPoPValidation(config DPoPValidationConfig) (*DPoPValidation, error) {
	if err := config.Options.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidDPoPConfiguration, err)
	}
	if config.Registry == nil {
		return nil, fmt.Errorf("%w: no replay registry", ErrInvalidDPoPConfiguration)
	}
	options := config.Options
	algorithms := slices.Clone(options.SigningAlgorithms)
	if len(algorithms) == 0 {
		algorithms = dpop.DefaultOptions().SigningAlgorithms
	}
	validation := &DPoPValidation{
		constructed: true,
		verifier:    dpop.NewVerifier(options),
		registry:    config.Registry,
		options:     options,
		algorithms:  algorithms,
		requestUri:  config.RequestUri,
	}
	if options.RequireNonce {
		if config.NonceKeys == nil {
			return nil, fmt.Errorf("%w: no nonce key source", ErrInvalidDPoPConfiguration)
		}
		current, previous, err := config.NonceKeys.NonceKeys()
		if err != nil {
			return nil, fmt.Errorf("%w: nonce keys unavailable: %w", ErrInvalidDPoPConfiguration, err)
		}
		if err := dpop.ValidateNonceKeys(current, previous); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidDPoPConfiguration, err)
		}
		if config.Resource == "" {
			return nil, fmt.Errorf("%w: no resource for the nonce surface", ErrInvalidDPoPConfiguration)
		}
		validation.sealer = dpop.NewNonceSealer(config.NonceKeys, options)
		validation.surface = resourceNonceSurfacePrefix + config.Resource
	}
	return validation, nil
}

// dpopPresentation is how one request presented its access token while DPoP
// validation is on.
type dpopPresentation struct {
	validation *DPoPValidation
	// proof is the accepted proof of a token presented with the DPoP
	// scheme, nil for a bearer token.
	proof *dpop.Proof
	// registered reports that the proof identifier was registered during
	// this authentication.
	registered bool
}

// dpopPresentation reads the access token of r while Options.DPoP is set. It
// returns token unchanged and a nil presentation when DPoP validation is
// off. A token already supplied by the MessageReceived event, or an
// Authorization header of any other scheme, counts as a bearer token and is
// returned unchanged. A DPoP scheme header yields its token once its proof
// passed the stateless checks, ath and, in the server nonce mode, the nonce
// included. A non-nil result ends the authentication with it.
func (h *Handler) dpopPresentation(r *http.Request, token string) (string, *dpopPresentation, *auth.Result) {
	validation := h.Options.DPoP
	if validation == nil {
		return token, nil, nil
	}
	if !validation.constructed {
		h.logDPoPUnavailable("DPoP validation was not made by NewDPoPValidation", errors.New("unconstructed DPoPValidation"))
		return token, nil, auth.Fail(ErrDPoPUnavailable)
	}
	presentation := &dpopPresentation{validation: validation}
	if strings.TrimSpace(token) != "" {
		return token, presentation, nil
	}
	dpopToken, found, malformed := dpopAuthorizationToken(r)
	if !found {
		return token, presentation, nil
	}
	if malformed {
		h.logDPoPRejection("malformed authorization header")
		return token, nil, auth.Fail(ErrDPoPMalformedAuthorization)
	}

	now := h.dpopNow()
	proof, err := validation.verifier.VerifyForResource(r.Header.Values(wicket.DPoPHeaderName), r.Method, validation.endpoint(r), dpopToken, now)
	if err != nil {
		h.logDPoPRejection(err.Error())
		return token, nil, auth.Fail(ErrDPoPProofRejected)
	}
	if validation.sealer != nil {
		if proof.Nonce == "" {
			h.logDPoPRejection("nonce missing")
			return token, nil, auth.Fail(ErrDPoPNonceRequired)
		}
		deadline, err := validation.sealer.Check(proof.Nonce, validation.surface, now)
		switch {
		case err == nil:
			proof.NonceDeadline = deadline
		case errors.Is(err, dpop.ErrInvalidNonce):
			h.logDPoPRejection(err.Error())
			return token, nil, auth.Fail(ErrDPoPNonceRequired)
		default:
			h.logDPoPUnavailable("DPoP server nonce unavailable", err)
			return token, nil, auth.Fail(ErrDPoPUnavailable)
		}
	}
	presentation.proof = &proof
	return dpopToken, presentation, nil
}

// dpopBinding judges a validated token against the scheme it was presented
// with and registers the proof identifier of a DPoP scheme request once per
// authentication. It returns nil when DPoP validation is off or the token
// passes; a non-nil result ends the authentication with it.
func (h *Handler) dpopBinding(r *http.Request, presentation *dpopPresentation, token SecurityToken) *auth.Result {
	if presentation == nil {
		return nil
	}
	thumbprint, bound, err := tokenConfirmationThumbprint(token)
	if err != nil {
		h.logDPoPRejection("token confirmation unreadable or malformed")
		return auth.Fail(ErrDPoPTokenBinding)
	}
	if presentation.proof == nil {
		if bound {
			h.logDPoPRejection("DPoP bound token presented as a bearer token")
			return auth.Fail(ErrDPoPTokenBinding)
		}
		return nil
	}
	if !bound {
		h.logDPoPRejection("token not bound to a proof key")
		return auth.Fail(ErrDPoPTokenBinding)
	}
	if !dpop.ThumbprintMatches(*presentation.proof, thumbprint) {
		h.logDPoPRejection("proof key does not match the token")
		return auth.Fail(ErrDPoPTokenBinding)
	}
	if presentation.registered {
		return nil
	}
	validation := presentation.validation
	err = dpop.Register(r.Context(), validation.registry, *presentation.proof, validation.options, h.dpopNow())
	switch {
	case err == nil:
		presentation.registered = true
		return nil
	case errors.Is(err, dpop.ErrReplayedProof):
		h.logDPoPRejection("replay")
		return auth.Fail(ErrDPoPProofRejected)
	default:
		// The text of the underlying error may carry the registry key, so
		// only its type is recorded.
		h.logDPoPUnavailable("DPoP proof could not be registered", err)
		return auth.Fail(ErrDPoPUnavailable)
	}
}

// tokenConfirmationThumbprint reads the proof key thumbprint the cnf claim
// of a token produced by the built-in validator binds it to. Any other
// token, an unreadable claim and a malformed cnf yield an error.
func tokenConfirmationThumbprint(token SecurityToken) (string, bool, error) {
	validated, ok := token.(*validatedToken)
	if !ok || validated == nil || validated.token == nil {
		return "", false, ErrDPoPTokenBinding
	}
	if !validated.token.Has(confirmationClaim) {
		return "", false, nil
	}
	var cnf any
	if err := validated.token.Get(confirmationClaim, &cnf); err != nil || cnf == nil {
		return "", false, ErrDPoPTokenBinding
	}
	return dpop.ConfirmationThumbprint(cnf)
}

// dpopAuthorizationToken reads a DPoP scheme Authorization header. found
// reports that the header names the DPoP scheme, matched without regard to
// case; malformed reports that it is not followed by one or more spaces and
// a token free of whitespace.
func dpopAuthorizationToken(r *http.Request) (token string, found bool, malformed bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, rest, _ := strings.Cut(header, " ")
	if !strings.EqualFold(scheme, wicket.AuthenticationSchemesAuthorizationHeaderDPoP) {
		return "", false, false
	}
	token = strings.TrimLeft(rest, " ")
	if token == "" || strings.ContainsFunc(token, isDPoPHeaderWhitespace) {
		return "", true, true
	}
	return token, true, false
}

func isDPoPHeaderWhitespace(c rune) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

// endpoint is the URI the htu claim of a proof sent with r has to name.
func (v *DPoPValidation) endpoint(r *http.Request) string {
	if v.requestUri != nil {
		return v.requestUri(r)
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.EscapedPath()
}

// dpopNow is the instant proofs and nonces are judged at.
func (h *Handler) dpopNow() time.Time {
	if h.Clock != nil {
		return h.Clock.Now()
	}
	return time.Now()
}

// logDPoPRejection records why a DPoP request was refused. The reason never
// carries a secret.
func (h *Handler) logDPoPRejection(reason string) {
	if h.Logger == nil {
		return
	}
	h.Logger.Debug("DPoP request rejected", slog.String("reason", reason))
}

// logDPoPUnavailable records that a DPoP proof could not be judged. The
// error text may carry a registry key or anything a key source returned, so
// only the type of the innermost cause is recorded.
func (h *Handler) logDPoPUnavailable(message string, err error) {
	if h.Logger == nil {
		return
	}
	h.Logger.Error(message, slog.String("error_type", fmt.Sprintf("%T", innermostCause(err))))
}

// innermostCause follows the wrap chain of err to its end, taking the last
// of several wrapped errors.
func innermostCause(err error) error {
	for {
		switch wrapper := err.(type) {
		case interface{ Unwrap() error }:
			next := wrapper.Unwrap()
			if next == nil {
				return err
			}
			err = next
		case interface{ Unwrap() []error }:
			causes := wrapper.Unwrap()
			if len(causes) == 0 {
				return err
			}
			err = causes[len(causes)-1]
		default:
			return err
		}
	}
}
