// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// knownPromptValidator stands in for the wrapped validator: it keeps the
// request parameters and settles prompt lists of known values only, ignoring
// a list that holds any other value.
type knownPromptValidator struct {
	err   error
	phase validators.AuthorizeRequestPhase
}

func (v *knownPromptValidator) Validate(_ context.Context, values url.Values, _ *claims.ClaimsPrincipal, phase validators.AuthorizeRequestPhase) *validators_models.AuthorizeRequestValidationResult {
	v.phase = phase
	request := validators_models.NewValidatedAuthorizeRequest()
	request.Raw = values
	if v.err != nil {
		return validators_models.NewAuthorizeRequestValidationResultWithErr(request, v.err, "inner")
	}
	known := func(raw string) []string {
		if strings.TrimSpace(raw) == "" {
			return nil
		}
		prompts := strings.Split(raw, " ")
		for _, prompt := range prompts {
			if !slices.Contains(wicket.SupportedPromptModes, prompt) {
				return nil
			}
		}
		return prompts
	}
	request.OriginalPromptModes = known(values.Get(wicket.AuthorizeRequestPrompt))
	request.SuppressedPromptModes = known(values.Get(wicket.SuppressedPrompt))
	request.PromptModes = slices.DeleteFunc(slices.Clone(request.OriginalPromptModes), func(p string) bool {
		return slices.Contains(request.SuppressedPromptModes, p)
	})
	return validators_models.NewAuthorizeRequestValidationResult(request)
}

func TestAuthorizePromptCreateValidator(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		prompt          string
		suppressed      string
		accountCreation bool
		wantErr         error
		wantDescription string
		wantOriginal    []string
		wantSuppressed  []string
		wantPrompts     []string
	}{
		"create": {
			prompt: "create", accountCreation: true,
			wantOriginal: []string{"create"}, wantPrompts: []string{"create"},
		},
		"create with consent": {
			prompt: "create consent", accountCreation: true,
			wantOriginal: []string{"create", "consent"}, wantPrompts: []string{"create", "consent"},
		},
		"create with login and account selection": {
			prompt: "login create select_account", accountCreation: true,
			wantOriginal: []string{"login", "create", "select_account"}, wantPrompts: []string{"login", "create", "select_account"},
		},
		"create not offered": {
			prompt:  "create",
			wantErr: wicket.AuthorizeErrorsInvalidRequest, wantDescription: "prompt value create is not supported",
		},
		"create with consent not offered": {
			prompt:  "consent create",
			wantErr: wicket.AuthorizeErrorsInvalidRequest, wantDescription: "prompt value create is not supported",
		},
		"none with create": {
			prompt: "none create", accountCreation: true,
			wantErr: wicket.AuthorizeErrorsInvalidRequest, wantDescription: "Invalid prompt",
		},
		"create with an unknown value": {
			prompt: "create foo", accountCreation: true,
		},
		"create with an unknown value not offered": {
			prompt: "create foo",
		},
		"without create": {
			prompt: "login consent", suppressed: "login",
			wantOriginal: []string{"login", "consent"}, wantSuppressed: []string{"login"}, wantPrompts: []string{"consent"},
		},
		"unknown value without create": {
			prompt: "login foo",
		},
		"returning from account creation": {
			prompt: "create consent", suppressed: "create", accountCreation: true,
			wantOriginal: []string{"create", "consent"}, wantSuppressed: []string{"create"}, wantPrompts: []string{"consent"},
		},
		"returning with login suppressed": {
			prompt: "create login", suppressed: "create login", accountCreation: true,
			wantOriginal: []string{"create", "login"}, wantSuppressed: []string{"create", "login"}, wantPrompts: []string{},
		},
		"suppressed create without a create prompt": {
			prompt: "login", suppressed: "create", accountCreation: true,
			wantOriginal: []string{"login"}, wantSuppressed: []string{"create"}, wantPrompts: []string{"login"},
		},
		"suppressed create not offered": {
			prompt: "login", suppressed: "create",
			wantOriginal: []string{"login"}, wantSuppressed: []string{"create"}, wantPrompts: []string{"login"},
		},
		"suppressed none with create": {
			prompt: "login", suppressed: "none create", accountCreation: true,
			wantErr: wicket.AuthorizeErrorsInvalidRequest, wantDescription: "Invalid prompt",
		},
		"suppressed create with an unknown value": {
			prompt: "login", suppressed: "create foo", accountCreation: true,
			wantOriginal: []string{"login"}, wantPrompts: []string{"login"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			values := url.Values{}
			if tc.prompt != "" {
				values.Set(wicket.AuthorizeRequestPrompt, tc.prompt)
			}
			if tc.suppressed != "" {
				values.Set(wicket.SuppressedPrompt, tc.suppressed)
			}
			inner := &knownPromptValidator{}
			validator := NewAuthorizePromptCreateValidator(inner, tc.accountCreation)

			result := validator.Validate(context.Background(), values, nil, validators.AuthorizeRequestPhaseInteractionReturn)

			if inner.phase != validators.AuthorizeRequestPhaseInteractionReturn {
				t.Fatalf("phase = %v", inner.phase)
			}
			if !errors.Is(result.Error, tc.wantErr) || result.Description != tc.wantDescription {
				t.Fatalf("result = %v %q, want %v %q", result.Error, result.Description, tc.wantErr, tc.wantDescription)
			}
			if result.ValidatedRequest == nil {
				t.Fatal("no validated request")
			}
			if tc.wantErr != nil {
				return
			}
			request := result.ValidatedRequest
			if !slices.Equal(request.OriginalPromptModes, tc.wantOriginal) {
				t.Fatalf("OriginalPromptModes = %v, want %v", request.OriginalPromptModes, tc.wantOriginal)
			}
			if !slices.Equal(request.SuppressedPromptModes, tc.wantSuppressed) {
				t.Fatalf("SuppressedPromptModes = %v, want %v", request.SuppressedPromptModes, tc.wantSuppressed)
			}
			if !slices.Equal(request.PromptModes, tc.wantPrompts) {
				t.Fatalf("PromptModes = %v, want %v", request.PromptModes, tc.wantPrompts)
			}
		})
	}
}

func TestAuthorizePromptCreateValidatorLeavesRequestsWithoutCreateUntouched(t *testing.T) {
	t.Parallel()

	values := url.Values{wicket.AuthorizeRequestPrompt: {"login"}}
	inner := &knownPromptValidator{}
	want := inner.Validate(context.Background(), values, nil, validators.AuthorizeRequestPhaseEntry).ValidatedRequest
	want.PromptModes = []string{"sentinel"}

	validator := NewAuthorizePromptCreateValidator(fixedResultValidator{request: want}, true)
	result := validator.Validate(context.Background(), values, nil, validators.AuthorizeRequestPhaseEntry)

	if result.ValidatedRequest != want || !slices.Equal(want.PromptModes, []string{"sentinel"}) {
		t.Fatalf("request changed: %v", want.PromptModes)
	}
}

func TestAuthorizePromptCreateValidatorPassesErrorsThrough(t *testing.T) {
	t.Parallel()

	failure := errors.New("inner failure")
	inner := &knownPromptValidator{err: failure}
	validator := NewAuthorizePromptCreateValidator(inner, false)

	result := validator.Validate(context.Background(), url.Values{wicket.AuthorizeRequestPrompt: {"create"}}, nil, validators.AuthorizeRequestPhaseEntry)

	if !errors.Is(result.Error, failure) || result.Description != "inner" {
		t.Fatalf("result = %v %q, want the inner error", result.Error, result.Description)
	}
	if validator.Inner() != inner || validator.AccountCreation() {
		t.Fatal("accessors do not report the construction")
	}
}

type fixedResultValidator struct {
	request *validators_models.ValidatedAuthorizeRequest
}

func (v fixedResultValidator) Validate(context.Context, url.Values, *claims.ClaimsPrincipal, validators.AuthorizeRequestPhase) *validators_models.AuthorizeRequestValidationResult {
	return validators_models.NewAuthorizeRequestValidationResult(v.request)
}

func TestAuthorizePromptCreateValidatorReadsPushedParameters(t *testing.T) {
	t.Parallel()

	request := validators_models.NewValidatedAuthorizeRequest()
	request.Raw = url.Values{
		wicket.AuthorizeRequestClientId:   {"client"},
		wicket.AuthorizeRequestRequestUri: {"urn:pushed"},
		wicket.SuppressedPrompt:           {"create"},
	}
	request.PushedRequestUri = "urn:pushed"
	request.PushedParameters = url.Values{
		wicket.AuthorizeRequestPrompt: {"create consent"},
		wicket.SuppressedPrompt:       {"create"},
	}

	result := NewAuthorizePromptCreateValidator(fixedResultValidator{request: request}, true).Validate(context.Background(), nil, nil, validators.AuthorizeRequestPhaseInteractionReturn)

	if result.Error != nil {
		t.Fatalf("result = %v %q", result.Error, result.Description)
	}
	if !slices.Equal(request.OriginalPromptModes, []string{"create", "consent"}) || !slices.Equal(request.PromptModes, []string{"consent"}) {
		t.Fatalf("prompts = %v / %v", request.OriginalPromptModes, request.PromptModes)
	}

	refused := NewAuthorizePromptCreateValidator(fixedResultValidator{request: request}, false).Validate(context.Background(), nil, nil, validators.AuthorizeRequestPhaseEntry)
	if !errors.Is(refused.Error, wicket.AuthorizeErrorsInvalidRequest) {
		t.Fatalf("result = %v, want invalid_request while not offered", refused.Error)
	}
}
