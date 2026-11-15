// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"encoding/base64"

	"github.com/gonewx/wicket"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// dpopKeyThumbprintLength is the length of an unpadded base64url SHA-256
// thumbprint.
const dpopKeyThumbprintLength = 43

// SetDPoPKeyBinding makes the validator accept the dpop_jkt parameter of an
// assembly with DPoP enabled. Without it the parameter is ignored.
func (v *AuthorizeRequestValidator) SetDPoPKeyBinding() {
	v.dpopKeyBinding = true
}

// validateDPoPKeyThumbprint reads the dpop_jkt parameter (RFC 9449 section
// 10) into the request. A present value has to be the unpadded base64url
// encoding of 32 bytes, in canonical form; anything else is an invalid
// request. It returns nil when the request may proceed.
func (v *AuthorizeRequestValidator) validateDPoPKeyThumbprint(request *validators_models.ValidatedAuthorizeRequest) *validators_models.AuthorizeRequestValidationResult {
	if !v.dpopKeyBinding {
		return nil
	}
	values, present := request.Raw[wicket.AuthorizeRequestDPoPJkt]
	if !present {
		return nil
	}
	if len(values) != 1 || !validDPoPKeyThumbprint(values[0]) {
		return invalid(request, wicket.AuthorizeErrorsInvalidRequest, "Invalid dpop_jkt")
	}
	request.DPoPKeyThumbprint = values[0]
	return nil
}

// validDPoPKeyThumbprint reports whether value is 43 characters that decode,
// as canonical unpadded base64url, to 32 bytes.
func validDPoPKeyThumbprint(value string) bool {
	if len(value) != dpopKeyThumbprintLength {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}
