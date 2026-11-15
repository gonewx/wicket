// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/pushedauth"
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const consumptionTestURI = "urn:ietf:params:oauth:request_uri:consumption-test"

// recordingConsumer records consumptions and answers them with err.
type recordingConsumer struct {
	err   error
	calls []string
	// generatorCalled reports whether the generator had run when Consume
	// was called.
	generator *countingGenerator
	sawCreate bool
}

func (c *recordingConsumer) Consume(_ context.Context, requestURI string, clientId string) error {
	c.calls = append(c.calls, requestURI+"|"+clientId)
	if c.generator != nil && c.generator.calls > 0 {
		c.sawCreate = true
	}
	return c.err
}

// countingGenerator counts Create calls.
type countingGenerator struct {
	calls    int
	response *responses_models.AuthorizeResponse
	err      error
}

func (g *countingGenerator) Create(context.Context, *validators_models.ValidatedAuthorizeRequest) (*responses_models.AuthorizeResponse, error) {
	g.calls++
	return g.response, g.err
}

func pushedRequest() *validators_models.ValidatedAuthorizeRequest {
	request := validRequest()
	request.PushedRequestUri = consumptionTestURI
	return request
}

func TestAuthorizeDispatchConsumesPushedRequests(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	tests := map[string]struct {
		validation   *validators_models.AuthorizeRequestValidationResult
		interaction  *responses_models.InteractionResponse
		generatorErr error
		consumeErr   error
		wantConsumed int
		wantCreate   int
		wantErr      bool
		wantResult   string
		wantProtoErr error
	}{
		"success consumes before issuing": {
			validation:   validators_models.NewAuthorizeRequestValidationResult(pushedRequest()),
			interaction:  responses_models.NewInteractionResponse(),
			wantConsumed: 1, wantCreate: 1, wantResult: "authorize",
		},
		"lost race issues nothing": {
			validation:   validators_models.NewAuthorizeRequestValidationResult(pushedRequest()),
			interaction:  responses_models.NewInteractionResponse(),
			consumeErr:   pushedauth.ErrRequestUriConsumed,
			wantConsumed: 1, wantCreate: 0, wantResult: "authorize", wantProtoErr: wicket.AuthorizeErrorsInvalidRequest,
		},
		"client gone issues nothing": {
			validation:   validators_models.NewAuthorizeRequestValidationResult(pushedRequest()),
			interaction:  responses_models.NewInteractionResponse(),
			consumeErr:   pushedauth.ErrClientRejected,
			wantConsumed: 1, wantCreate: 0, wantResult: "authorize", wantProtoErr: wicket.AuthorizeErrorsInvalidRequest,
		},
		"consumption failure is a process error": {
			validation:   validators_models.NewAuthorizeRequestValidationResult(pushedRequest()),
			interaction:  responses_models.NewInteractionResponse(),
			consumeErr:   boom,
			wantConsumed: 1, wantCreate: 0, wantErr: true,
		},
		"validation error consumes": {
			validation:   validators_models.NewAuthorizeRequestValidationResultWithErr(pushedRequest(), wicket.AuthorizeErrorsInvalidScope, ""),
			interaction:  responses_models.NewInteractionResponse(),
			wantConsumed: 1, wantResult: "authorize", wantProtoErr: wicket.AuthorizeErrorsInvalidScope,
		},
		"validation error ignores a consumed request": {
			validation:   validators_models.NewAuthorizeRequestValidationResultWithErr(pushedRequest(), wicket.AuthorizeErrorsInvalidScope, ""),
			interaction:  responses_models.NewInteractionResponse(),
			consumeErr:   pushedauth.ErrRequestUriConsumed,
			wantConsumed: 1, wantResult: "authorize", wantProtoErr: wicket.AuthorizeErrorsInvalidScope,
		},
		"validation error with consumption failure is a process error": {
			validation:   validators_models.NewAuthorizeRequestValidationResultWithErr(pushedRequest(), wicket.AuthorizeErrorsInvalidScope, ""),
			interaction:  responses_models.NewInteractionResponse(),
			consumeErr:   boom,
			wantConsumed: 1, wantErr: true,
		},
		"interaction error consumes": {
			validation:   validators_models.NewAuthorizeRequestValidationResult(pushedRequest()),
			interaction:  &responses_models.InteractionResponse{Error: wicket.AuthorizeErrorsLoginRequired},
			wantConsumed: 1, wantResult: "authorize", wantProtoErr: wicket.AuthorizeErrorsLoginRequired,
		},
		"generator error consumes once": {
			validation:   validators_models.NewAuthorizeRequestValidationResult(pushedRequest()),
			interaction:  responses_models.NewInteractionResponse(),
			generatorErr: wicket.AuthorizeErrorsServerError,
			wantConsumed: 2, wantCreate: 1, wantResult: "authorize", wantProtoErr: wicket.AuthorizeErrorsServerError,
		},
		"login redirect does not consume": {
			validation:   validators_models.NewAuthorizeRequestValidationResult(pushedRequest()),
			interaction:  &responses_models.InteractionResponse{IsLogin: true},
			wantConsumed: 0, wantResult: "login",
		},
		"consent redirect does not consume": {
			validation:   validators_models.NewAuthorizeRequestValidationResult(pushedRequest()),
			interaction:  &responses_models.InteractionResponse{IsConsent: true},
			wantConsumed: 0, wantResult: "consent",
		},
		"custom redirect does not consume": {
			validation:   validators_models.NewAuthorizeRequestValidationResult(pushedRequest()),
			interaction:  &responses_models.InteractionResponse{RedirectUrl: "/custom"},
			wantConsumed: 0, wantResult: "custom",
		},
		"ordinary request is not consumed": {
			validation:   validators_models.NewAuthorizeRequestValidationResult(validRequest()),
			interaction:  responses_models.NewInteractionResponse(),
			wantConsumed: 0, wantCreate: 1, wantResult: "authorize",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			generator := &countingGenerator{response: responses_models.NewAuthorizeResponse(), err: tc.generatorErr}
			consumer := &recordingConsumer{err: tc.consumeErr, generator: generator}
			base := authorizeBaseHandler{
				interaction: &fakeInteractionGenerator{response: tc.interaction},
				generator:   generator,
				session:     &fakeUserSession{},
				pushed:      consumer,
			}
			result, err := base.dispatch(context.Background(), tc.validation, nil)
			if len(consumer.calls) != tc.wantConsumed {
				t.Fatalf("consumed %d times, want %d", len(consumer.calls), tc.wantConsumed)
			}
			if tc.wantConsumed > 0 && consumer.calls[0] != consumptionTestURI+"|some-client" {
				t.Fatalf("consumed %q", consumer.calls[0])
			}
			if consumer.sawCreate && tc.generatorErr == nil {
				t.Fatal("consumed after the response was created")
			}
			if generator.calls != tc.wantCreate {
				t.Fatalf("generator called %d times, want %d", generator.calls, tc.wantCreate)
			}
			if tc.wantErr {
				if err == nil {
					t.Fatalf("dispatch = %T, nil; want a process error", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("dispatch error = %v", err)
			}
			switch tc.wantResult {
			case "authorize":
				authorize, ok := result.(*results.AuthorizeResult)
				if !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
				if !errors.Is(authorize.Response.Error, tc.wantProtoErr) || (tc.wantProtoErr == nil && authorize.Response.Error != nil) {
					t.Fatalf("response error = %v, want %v", authorize.Response.Error, tc.wantProtoErr)
				}
			case "login":
				if _, ok := result.(*results.LoginPageResult); !ok {
					t.Fatalf("result = %T, want login", result)
				}
			case "consent":
				if _, ok := result.(*results.ConsentPageResult); !ok {
					t.Fatalf("result = %T, want consent", result)
				}
			case "custom":
				if _, ok := result.(*results.CustomRedirectResult); !ok {
					t.Fatalf("result = %T, want custom redirect", result)
				}
			}
		})
	}
}
