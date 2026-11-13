// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/handlers/results"
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// The base handler carries the validate→interaction→result pipeline shared by
// the front-channel authorize entry and the post-interaction callback. These
// tests drive that shared core directly so its precedence rules are pinned
// independent of either entry point's parameter gathering.

func newBaseHandler(
	validation *validators_models.AuthorizeRequestValidationResult,
	interaction *responses_models.InteractionResponse,
	response *responses_models.AuthorizeResponse,
	generatorErr error,
) authorizeBaseHandler {
	return authorizeBaseHandler{
		validator:   &fakeAuthorizeRequestValidator{result: validation},
		interaction: &fakeInteractionGenerator{response: interaction},
		generator:   &fakeAuthorizeResponseGenerator{response: response, err: generatorErr},
		session:     &fakeUserSession{},
	}
}

func TestAuthorizeBaseHandlerDispatchPrecedence(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		validation  func() *validators_models.AuthorizeRequestValidationResult
		interaction *responses_models.InteractionResponse
		response    *responses_models.AuthorizeResponse
		generator   error
		assert      func(t *testing.T, result endpointResult)
	}{
		"validation error precedes interaction": {
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResultWithErr(validRequest(), wicket.AuthorizeErrorsInvalidRequest, "")
			},
			interaction: &responses_models.InteractionResponse{IsLogin: true},
			assert: func(t *testing.T, result endpointResult) {
				authorizeResult, ok := result.(*results.AuthorizeResult)
				if !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
				if authorizeResult.Response.Error == nil {
					t.Fatal("response error = nil, want validation error to win over interaction")
				}
			},
		},
		"interaction error precedes login and consent": {
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResult(validRequest())
			},
			interaction: &responses_models.InteractionResponse{
				Error:     wicket.AuthorizeErrorsLoginRequired,
				IsLogin:   true,
				IsConsent: true,
			},
			assert: func(t *testing.T, result endpointResult) {
				if _, ok := result.(*results.AuthorizeResult); !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult (interaction error wins)", result)
				}
			},
		},
		"login precedes consent": {
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResult(validRequest())
			},
			interaction: &responses_models.InteractionResponse{IsLogin: true, IsConsent: true},
			assert: func(t *testing.T, result endpointResult) {
				if _, ok := result.(*results.LoginPageResult); !ok {
					t.Fatalf("result = %T, want *results.LoginPageResult (login wins over consent)", result)
				}
			},
		},
		"generator error surfaces as error authorize result not process error": {
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResult(validRequest())
			},
			interaction: responses_models.NewInteractionResponse(),
			generator:   wicket.AuthorizeErrorsInvalidRequest,
			assert: func(t *testing.T, result endpointResult) {
				authorizeResult, ok := result.(*results.AuthorizeResult)
				if !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
				if authorizeResult.Response.Error == nil {
					t.Fatal("response error = nil, want generator failure carried to the client via result")
				}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			base := newBaseHandler(tt.validation(), tt.interaction, tt.response, tt.generator)
			result, err := base.dispatch(context.Background(), tt.validation(), nil)
			if err != nil {
				t.Fatalf("dispatch returned process error %v, want nil (protocol errors travel via result)", err)
			}
			tt.assert(t, result)
		})
	}
}
