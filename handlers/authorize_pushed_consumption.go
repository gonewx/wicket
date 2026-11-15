// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"errors"
	"fmt"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/pushedauth"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// PushedAuthorizationConsumer consumes pushed authorization requests (RFC
// 9126) once the authorize endpoint answers the client. pushedauth.Service
// implements it.
type PushedAuthorizationConsumer interface {
	// Consume reloads the client and atomically takes the pushed request.
	// It returns an error matching pushedauth.ErrClientRejected or
	// pushedauth.ErrRequestUriConsumed when the request cannot be consumed
	// for that reason; any other error is an infrastructure failure.
	Consume(ctx context.Context, requestURI string, clientId string) error
}

var _ PushedAuthorizationConsumer = (*pushedauth.Service)(nil)

// pushedConsumptionRefused reports whether err says the pushed request cannot
// be consumed for a protocol reason rather than an infrastructure failure.
func pushedConsumptionRefused(err error) bool {
	return errors.Is(err, pushedauth.ErrClientRejected) || errors.Is(err, pushedauth.ErrRequestUriConsumed)
}

// consumePushedBeforeIssue consumes the pushed request of request before an
// authorization response is issued. A request that was not pushed returns
// (nil, nil). A refused consumption, a client that is gone or a request that
// was consumed by someone else, returns an invalid_request result, and no
// response may be issued; any other failure returns the error.
func (h *authorizeBaseHandler) consumePushedBeforeIssue(ctx context.Context, request *validators_models.ValidatedAuthorizeRequest) (endpointResult, error) {
	if request == nil || request.PushedRequestUri == "" || h.pushed == nil {
		return nil, nil
	}
	err := h.pushed.Consume(ctx, request.PushedRequestUri, request.ClientId)
	switch {
	case err == nil:
		return nil, nil
	case pushedConsumptionRefused(err):
		return h.errorResult(request, wicket.AuthorizeErrorsInvalidRequest, ""), nil
	default:
		return nil, fmt.Errorf("consume pushed authorization request: %w", err)
	}
}

// pushedErrorResult is errorResult for an error that answers the client: the
// pushed request of request, if any, is consumed first. A request that was
// already consumed or whose client is gone does not change the answer; any
// other failure returns the error.
func (h *authorizeBaseHandler) pushedErrorResult(ctx context.Context, request *validators_models.ValidatedAuthorizeRequest, err error, description string) (endpointResult, error) {
	if request != nil && request.PushedRequestUri != "" && h.pushed != nil {
		if consumeErr := h.pushed.Consume(ctx, request.PushedRequestUri, request.ClientId); consumeErr != nil && !pushedConsumptionRefused(consumeErr) {
			return nil, fmt.Errorf("consume pushed authorization request: %w", consumeErr)
		}
	}
	return h.errorResult(request, err, description), nil
}
