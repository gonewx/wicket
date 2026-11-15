// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"net/url"
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// promptCreateNotSupported is the error description of a create prompt
// received while no account creation page is configured.
const promptCreateNotSupported = "prompt value create is not supported"

// AuthorizePromptCreateValidator decorates an authorize request validator so
// that the create prompt value is understood. The wrapped validator ignores a
// prompt list that holds a value it does not know; the decorator settles the
// prompt and suppressed_prompt lists whose only such value is create:
//
//   - while account creation is not offered, a create prompt is refused with
//     invalid_request;
//   - none together with any other value is refused with invalid_request;
//   - otherwise the list is recorded and the effective prompt modes are
//     recomputed.
//
// Lists holding another unknown value, and requests without create, are left
// as the wrapped validator settled them. An error result of the wrapped
// validator is returned unchanged.
type AuthorizePromptCreateValidator struct {
	inner           validators.AuthorizeRequestValidator
	accountCreation bool
}

// NewAuthorizePromptCreateValidator wraps inner. accountCreation says whether
// the assembly offers an account creation page for the create prompt.
func NewAuthorizePromptCreateValidator(inner validators.AuthorizeRequestValidator, accountCreation bool) *AuthorizePromptCreateValidator {
	return &AuthorizePromptCreateValidator{inner: inner, accountCreation: accountCreation}
}

// Inner returns the wrapped validator.
func (v *AuthorizePromptCreateValidator) Inner() validators.AuthorizeRequestValidator {
	return v.inner
}

// AccountCreation reports whether the create prompt is accepted.
func (v *AuthorizePromptCreateValidator) AccountCreation() bool {
	return v.accountCreation
}

func (v *AuthorizePromptCreateValidator) Validate(ctx context.Context, values url.Values, subject *claims.ClaimsPrincipal, phase validators.AuthorizeRequestPhase) *validators_models.AuthorizeRequestValidationResult {
	result := v.inner.Validate(ctx, values, subject, phase)
	if result == nil || result.ValidationResult == nil || result.Error != nil || result.ValidatedRequest == nil {
		return result
	}
	request := result.ValidatedRequest
	parameters := validatedParameters(request)

	changed := false
	if prompts, ok := createPromptList(parameters.Get(wicket.AuthorizeRequestPrompt)); ok {
		if !v.accountCreation {
			return validators_models.NewAuthorizeRequestValidationResultWithErr(request, wicket.AuthorizeErrorsInvalidRequest, promptCreateNotSupported)
		}
		if invalidNoneCombination(prompts) {
			return validators_models.NewAuthorizeRequestValidationResultWithErr(request, wicket.AuthorizeErrorsInvalidRequest, "Invalid prompt")
		}
		request.OriginalPromptModes = prompts
		changed = true
	}
	if prompts, ok := createPromptList(parameters.Get(wicket.SuppressedPrompt)); ok {
		if invalidNoneCombination(prompts) {
			return validators_models.NewAuthorizeRequestValidationResultWithErr(request, wicket.AuthorizeErrorsInvalidRequest, "Invalid prompt")
		}
		request.SuppressedPromptModes = prompts
		changed = true
	}
	if changed {
		request.PromptModes = utils.Except(request.OriginalPromptModes, request.SuppressedPromptModes)
	}
	return result
}

// validatedParameters returns the parameters the wrapped validator settled
// the prompt lists from: the pushed parameters of a request resolved from a
// pushed authorization request, whose Raw then holds only the handle, and
// Raw otherwise.
func validatedParameters(request *validators_models.ValidatedAuthorizeRequest) url.Values {
	if request.PushedRequestUri != "" && request.PushedParameters != nil {
		return request.PushedParameters
	}
	return request.Raw
}

// createPromptList splits a space separated prompt list and reports whether
// it holds create and otherwise only known prompt values.
func createPromptList(raw string) ([]string, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, false
	}
	prompts := strings.Split(raw, " ")
	if !slices.Contains(prompts, wicket.PromptModesCreate) {
		return nil, false
	}
	for _, prompt := range prompts {
		if prompt != wicket.PromptModesCreate && !slices.Contains(wicket.SupportedPromptModes, prompt) {
			return nil, false
		}
	}
	return prompts, true
}

func invalidNoneCombination(prompts []string) bool {
	return slices.Contains(prompts, wicket.PromptModesNone) && len(prompts) > 1
}
