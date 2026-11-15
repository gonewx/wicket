// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// fakeUserSession is a stand-in session that returns a fixed subject. Only
// GetUser participates in the pipeline under test; the rest satisfy the
// interface.
type fakeUserSession struct {
	user *claims.ClaimsPrincipal
}

func (s *fakeUserSession) EnsureSessionIdCookie(ctx context.Context) error { return nil }
func (s *fakeUserSession) RemoveSessionIdCookie() error                    { return nil }
func (s *fakeUserSession) CreateSessionId(ctx context.Context, principal *claims.ClaimsPrincipal, properties *auth.Properties) (string, error) {
	return "", nil
}
func (s *fakeUserSession) GetSessionId() string                                   { return "" }
func (s *fakeUserSession) GetClientList() ([]string, error)                       { return nil, nil }
func (s *fakeUserSession) GetUser() *claims.ClaimsPrincipal                       { return s.user }
func (s *fakeUserSession) AddClientId(ctx context.Context, clientId string) error { return nil }
func (s *fakeUserSession) Item(string) (any, bool)                                { return nil, false }
func (s *fakeUserSession) SetItem(string, any)                                    {}

// fakeAuthorizeRequestValidator returns a preset validation result regardless of
// the incoming parameters.
type fakeAuthorizeRequestValidator struct {
	result *validators_models.AuthorizeRequestValidationResult
}

func (v *fakeAuthorizeRequestValidator) Validate(ctx context.Context, values url.Values, subject *claims.ClaimsPrincipal, phase validators.AuthorizeRequestPhase) *validators_models.AuthorizeRequestValidationResult {
	return v.result
}

// fakeInteractionGenerator returns a preset interaction decision.
type fakeInteractionGenerator struct {
	response *responses_models.InteractionResponse
}

func (g *fakeInteractionGenerator) Handle(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) *responses_models.InteractionResponse {
	return g.response
}
func (g *fakeInteractionGenerator) HandleLogin(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest) *responses_models.InteractionResponse {
	return nil
}
func (g *fakeInteractionGenerator) HandleConsent(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest, consent *messages.ConsentResponse) *responses_models.InteractionResponse {
	return nil
}

// fakeAuthorizeResponseGenerator returns a preset authorize response or error.
type fakeAuthorizeResponseGenerator struct {
	response *responses_models.AuthorizeResponse
	err      error
}

func (g *fakeAuthorizeResponseGenerator) Create(ctx context.Context, req *validators_models.ValidatedAuthorizeRequest) (*responses_models.AuthorizeResponse, error) {
	return g.response, g.err
}

func validRequest() *validators_models.ValidatedAuthorizeRequest {
	req := validators_models.NewValidatedAuthorizeRequest()
	req.ClientId = "some-client"
	req.GrantType = wicket.GrantTypeAuthorizationCode
	req.RedirectUri = "https://client.example/callback"
	return req
}

func sessionBoundRequest() *validators_models.ValidatedAuthorizeRequest {
	req := validRequest()
	req.IsOpenIdRequest = true
	req.SessionId = "some-session"
	req.PromptModes = []string{wicket.PromptModesNone}
	return req
}

func newAuthorizeHandler(
	validation *validators_models.AuthorizeRequestValidationResult,
	interaction *responses_models.InteractionResponse,
	response *responses_models.AuthorizeResponse,
) *AuthorizeHandler {
	return NewAuthorizeHandler(
		&fakeAuthorizeRequestValidator{result: validation},
		&fakeInteractionGenerator{response: interaction},
		&fakeAuthorizeResponseGenerator{response: response},
		&fakeUserSession{},
		nil,
	)
}

func TestAuthorizeHandlerResultDispatch(t *testing.T) {
	t.Parallel()

	const errorDescription = "some description"

	for name, tt := range map[string]struct {
		method      string
		validation  func() *validators_models.AuthorizeRequestValidationResult
		interaction *responses_models.InteractionResponse
		response    *responses_models.AuthorizeResponse
		assert      func(t *testing.T, result endpointResult)
	}{
		"success authorize request builds authorize result": {
			method: http.MethodGet,
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResult(validRequest())
			},
			interaction: responses_models.NewInteractionResponse(),
			response:    responses_models.NewAuthorizeResponse(),
			assert: func(t *testing.T, result endpointResult) {
				authorizeResult, ok := result.(*results.AuthorizeResult)
				if !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
				if authorizeResult.Response.Error != nil {
					t.Fatalf("response error = %v, want nil", authorizeResult.Response.Error)
				}
			},
		},
		"validation error builds error authorize result": {
			method: http.MethodGet,
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResultWithErr(validRequest(), wicket.AuthorizeErrorsInvalidRequest, errorDescription)
			},
			interaction: responses_models.NewInteractionResponse(),
			assert: func(t *testing.T, result endpointResult) {
				authorizeResult, ok := result.(*results.AuthorizeResult)
				if !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
				if authorizeResult.Response.Error == nil {
					t.Fatal("response error = nil, want non-nil")
				}
			},
		},
		"openid session validation error carries session_state": {
			method: http.MethodGet,
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResultWithErr(sessionBoundRequest(), wicket.AuthorizeErrorsInvalidRequest, "")
			},
			interaction: responses_models.NewInteractionResponse(),
			assert: func(t *testing.T, result endpointResult) {
				authorizeResult, ok := result.(*results.AuthorizeResult)
				if !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
				if authorizeResult.Response.Error == nil {
					t.Fatal("response error = nil, want non-nil")
				}
				if authorizeResult.Response.SessionState == "" {
					t.Fatal("session_state = empty, want non-empty")
				}
			},
		},
		"interaction consent builds consent page result": {
			method: http.MethodGet,
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResult(validRequest())
			},
			interaction: &responses_models.InteractionResponse{IsConsent: true},
			assert: func(t *testing.T, result endpointResult) {
				if _, ok := result.(*results.ConsentPageResult); !ok {
					t.Fatalf("result = %T, want *results.ConsentPageResult", result)
				}
			},
		},
		"interaction login builds login page result": {
			method: http.MethodGet,
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResult(validRequest())
			},
			interaction: &responses_models.InteractionResponse{IsLogin: true},
			assert: func(t *testing.T, result endpointResult) {
				if _, ok := result.(*results.LoginPageResult); !ok {
					t.Fatalf("result = %T, want *results.LoginPageResult", result)
				}
			},
		},
		"interaction error builds error authorize result": {
			method: http.MethodGet,
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResult(validRequest())
			},
			interaction: &responses_models.InteractionResponse{Error: wicket.AuthorizeErrorsLoginRequired},
			assert: func(t *testing.T, result endpointResult) {
				authorizeResult, ok := result.(*results.AuthorizeResult)
				if !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
				if authorizeResult.Response.Error == nil {
					t.Fatal("response error = nil, want non-nil")
				}
			},
		},
		"interaction error description is propagated": {
			method: http.MethodGet,
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResult(validRequest())
			},
			interaction: &responses_models.InteractionResponse{
				Error:            wicket.AuthorizeErrorsAccessDenied,
				ErrorDescription: errorDescription,
			},
			assert: func(t *testing.T, result endpointResult) {
				authorizeResult, ok := result.(*results.AuthorizeResult)
				if !ok {
					t.Fatalf("result = %T, want *results.AuthorizeResult", result)
				}
				if authorizeResult.Response.ErrorDescription != errorDescription {
					t.Fatalf("error description = %q, want %q", authorizeResult.Response.ErrorDescription, errorDescription)
				}
			},
		},
		"interaction custom redirect builds custom redirect result": {
			method: http.MethodGet,
			validation: func() *validators_models.AuthorizeRequestValidationResult {
				return validators_models.NewAuthorizeRequestValidationResult(validRequest())
			},
			interaction: &responses_models.InteractionResponse{RedirectUrl: "https://custom.example/interaction"},
			assert: func(t *testing.T, result endpointResult) {
				if _, ok := result.(*results.CustomRedirectResult); !ok {
					t.Fatalf("result = %T, want *results.CustomRedirectResult", result)
				}
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := newAuthorizeHandler(tt.validation(), tt.interaction, tt.response)
			req := httptest.NewRequest(tt.method, "https://wicket.test"+wicket.ProtocolRoutePathsAuthorize+"?client_id=some-client", nil)

			result, err := handler.result(req)
			if err != nil {
				t.Fatalf("result: %v", err)
			}
			tt.assert(t, result)
		})
	}
}

func TestAuthorizeHandlerRejectsNonFormPost(t *testing.T) {
	t.Parallel()

	handler := newAuthorizeHandler(
		validators_models.NewAuthorizeRequestValidationResult(validRequest()),
		responses_models.NewInteractionResponse(),
		responses_models.NewAuthorizeResponse(),
	)
	req := httptest.NewRequest(http.MethodPost, "https://wicket.test"+wicket.ProtocolRoutePathsAuthorize, strings.NewReader(`{"client_id":"x"}`))
	req.Header.Set("Content-Type", "application/json")

	result, err := handler.result(req)
	if err != nil {
		t.Fatalf("result: %v", err)
	}
	statusResult, ok := result.(*results.StatusCodeResult)
	if !ok {
		t.Fatalf("result = %T, want *results.StatusCodeResult", result)
	}
	if statusResult.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d", statusResult.StatusCode, http.StatusUnsupportedMediaType)
	}
}
