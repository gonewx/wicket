// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// PushedAuthorizationResolver resolves pushed authorization requests for the
// authorize request validator. pushedauth.Service implements it.
type PushedAuthorizationResolver interface {
	// Resolve returns the parameters of the pushed request requestURI names
	// for clientId, and the entry receipt the request carries from now on.
	// An unusable request_uri returns an error matching
	// pushedauth.ErrRequestUriInvalid; any other error is a store failure.
	Resolve(ctx context.Context, requestURI string, clientId string, receipt string, interactionReturn bool) (url.Values, string, error)
	// Required reports whether client may use the authorize endpoint only
	// through a pushed request_uri.
	Required(client *storage_models.Client) bool
}

var _ PushedAuthorizationResolver = (*pushedauth.Service)(nil)

// AuthorizeRequestPushedStage is the pushed authorization step of authorize
// request validation. It runs once the client is loaded and before any
// request object is loaded. A nil stage stands for pushed authorization not
// being enabled: a pushed request_uri is then rejected outright.
type AuthorizeRequestPushedStage struct {
	resolver PushedAuthorizationResolver
}

// NewAuthorizeRequestPushedStage builds the stage of an assembly with pushed
// authorization enabled.
func NewAuthorizeRequestPushedStage(resolver PushedAuthorizationResolver) *AuthorizeRequestPushedStage {
	return &AuthorizeRequestPushedStage{resolver: resolver}
}

// Bind applies the pushed authorization rules of phase to request, whose
// client is loaded.
//
//   - Push: a request_uri is refused.
//   - Entry and InteractionReturn: a request_uri carrying the pushed
//     authorization prefix is resolved, never fetched; once resolved, a copy
//     of the pushed parameters becomes request.Raw for the rest of the
//     validation, and only the server's suppressed prompt marker is carried
//     over from the presented parameters, on a validated round trip only. A request without a pushed
//     request_uri is refused when the client must push.
//
// The returned settle function must run once validation ends, whatever its
// outcome. For a bound request it moves the working parameters into
// PushedParameters and leaves Raw with client_id, request_uri, the entry
// receipt and the carried marker only. It does nothing otherwise.
func (s *AuthorizeRequestPushedStage) Bind(ctx context.Context, request *validators_models.ValidatedAuthorizeRequest, phase validators.AuthorizeRequestPhase) (*validators_models.AuthorizeRequestValidationResult, func()) {
	noop := func() {}
	presented := request.Raw
	requestURI := strings.TrimSpace(presented.Get(wicket.AuthorizeRequestRequestUri))

	if phase == validators.AuthorizeRequestPhasePush {
		if _, ok := presented[wicket.AuthorizeRequestRequestUri]; ok {
			return pushedInvalid(request, wicket.AuthorizeErrorsInvalidRequest, "request_uri is not allowed in a pushed authorization request"), noop
		}
		return pushedValid(request), noop
	}

	if !strings.HasPrefix(requestURI, storage.PushedAuthorizationRequestURIPrefix) {
		if s != nil && s.resolver.Required(request.Client) {
			return pushedInvalid(request, wicket.AuthorizeErrorsInvalidRequest, "Client must use a pushed authorization request"), noop
		}
		return pushedValid(request), noop
	}
	if s == nil {
		return pushedInvalid(request, wicket.AuthorizeErrorsInvalidRequestUri, ""), noop
	}

	presentedReceipt := presented.Get(wicket.AuthorizeRequestPushedEntryReceipt)
	parameters, receipt, err := s.resolver.Resolve(ctx, requestURI, request.ClientId, presentedReceipt, phase == validators.AuthorizeRequestPhaseInteractionReturn)
	if err != nil {
		if errors.Is(err, pushedauth.ErrRequestUriInvalid) {
			return pushedInvalid(request, wicket.AuthorizeErrorsInvalidRequestUri, ""), noop
		}
		return pushedInvalid(request, wicket.AuthorizeErrorsServerError, ""), noop
	}

	// The suppressed prompt marker is the server's own, written before an
	// interaction redirect; it is carried over only on a validated round
	// trip, so a marker added to an entry URL cannot strip a pushed prompt.
	suppressed, carried := presented[wicket.SuppressedPrompt]
	roundTrip := phase == validators.AuthorizeRequestPhaseInteractionReturn && presentedReceipt != "" && receipt == presentedReceipt
	carried = carried && roundTrip
	suppressed = slices.Clone(suppressed)
	working := cloneValues(parameters)
	delete(working, wicket.SuppressedPrompt)
	delete(working, wicket.AuthorizeRequestPushedEntryReceipt)
	if carried {
		working[wicket.SuppressedPrompt] = slices.Clone(suppressed)
	}
	request.Raw = working

	clientId := request.ClientId
	settle := func() {
		request.PushedAuthorizationRequestValues = validators_models.PushedAuthorizationRequestValues{
			PushedRequestUri: requestURI,
			PushedParameters: request.Raw,
		}
		raw := url.Values{
			wicket.AuthorizeRequestClientId:           {clientId},
			wicket.AuthorizeRequestRequestUri:         {requestURI},
			wicket.AuthorizeRequestPushedEntryReceipt: {receipt},
		}
		if carried {
			raw[wicket.SuppressedPrompt] = slices.Clone(suppressed)
		}
		request.Raw = raw
	}
	return pushedValid(request), settle
}

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, list := range values {
		cloned[key] = slices.Clone(list)
	}
	return cloned
}

func pushedValid(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {
	return validators_models.NewAuthorizeRequestValidationResult(request)
}

func pushedInvalid(request *validators_models.ValidatedAuthorizeRequest, err error, description string) *validators_models.AuthorizeRequestValidationResult {
	return validators_models.NewAuthorizeRequestValidationResultWithErr(request, err, description)
}
