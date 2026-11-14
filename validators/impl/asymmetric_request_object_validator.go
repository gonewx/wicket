// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"

	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// asymmetricRequestObjectSigningAlgorithms are the JWS algorithms a request
// object may be signed with while only asymmetric signatures are accepted.
var asymmetricRequestObjectSigningAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// AsymmetricRequestObjectSigningAlgorithms returns a copy of the algorithms
// the asymmetric request object validator accepts.
func AsymmetricRequestObjectSigningAlgorithms() []string {
	return slices.Clone(asymmetricRequestObjectSigningAlgorithms)
}

// errSymmetricRequestObject is returned for every request object the
// decorator refuses. Its text never carries the request object.
var errSymmetricRequestObject = errors.New("request object is not signed with an accepted asymmetric algorithm")

// AsymmetricRequestObjectValidator decorates a request object validator so
// that only request objects signed with an asymmetric algorithm are
// accepted. The header algorithm is checked before anything else, and the
// wrapped validator only ever sees the client's non-symmetric keys: a key
// that names its own algorithm is used with that algorithm whatever the
// header says, so the header check alone could be bypassed.
type AsymmetricRequestObjectValidator struct {
	inner validators.JwtRequestValidator
}

var _ validators.JwtRequestValidator = (*AsymmetricRequestObjectValidator)(nil)

// NewAsymmetricRequestObjectValidator wraps inner.
func NewAsymmetricRequestObjectValidator(inner validators.JwtRequestValidator) *AsymmetricRequestObjectValidator {
	return &AsymmetricRequestObjectValidator{inner: inner}
}

// Inner returns the wrapped validator.
func (v *AsymmetricRequestObjectValidator) Inner() validators.JwtRequestValidator {
	return v.inner
}

// Validate refuses a request object that is not a compact serialization
// with an accepted asymmetric header algorithm, and otherwise hands a copy
// of the context, whose client carries no symmetric key, to the wrapped
// validator. A refusal is always (nil, error).
func (v *AsymmetricRequestObjectValidator) Validate(ctx *validators_contexts.JwtRequestValidationContext) (*validators_models.JwtRequestValidationResult, error) {
	if ctx == nil || ctx.Client == nil {
		return nil, errSymmetricRequestObject
	}
	if !asymmetricHeaderAlgorithm(ctx.JwtTokenString) {
		return nil, errSymmetricRequestObject
	}

	client := *ctx.Client
	client.ClientSecrets = withoutSymmetricKeys(ctx.Client.ClientSecrets)
	stripped := *ctx
	stripped.Client = &client
	return v.inner.Validate(&stripped)
}

// asymmetricHeaderAlgorithm reports whether token is a JWS compact
// serialization whose protected header names an accepted algorithm.
func asymmetricHeaderAlgorithm(token string) bool {
	segments := strings.Split(token, ".")
	if len(segments) != 3 || segments[0] == "" {
		return false
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return false
	}
	algorithm, ok := exactAlgorithmMember(rawHeader)
	return ok && slices.Contains(asymmetricRequestObjectSigningAlgorithms, algorithm)
}

// exactAlgorithmMember walks the top-level members of a JSON object header
// and returns the string value of the member named exactly "alg". It fails
// when that member is missing, appears more than once, is not a string, or
// when any other member name equals "alg" without regard to case.
func exactAlgorithmMember(rawHeader []byte) (string, bool) {
	decoder := json.NewDecoder(bytes.NewReader(rawHeader))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return "", false
	}
	algorithm, found := "", false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return "", false
		}
		name, ok := token.(string)
		if !ok {
			return "", false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", false
		}
		if !strings.EqualFold(name, "alg") {
			continue
		}
		if name != "alg" || found {
			return "", false
		}
		if err := json.Unmarshal(value, &algorithm); err != nil {
			return "", false
		}
		found = true
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return "", false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return "", false
	}
	return algorithm, found
}

// withoutSymmetricKeys returns a new slice holding every secret that does
// not yield a symmetric (oct) key. Each secret is judged by the same key
// parsing the client applies, one secret at a time.
func withoutSymmetricKeys(secrets []*storage_models.Secret) []*storage_models.Secret {
	kept := make([]*storage_models.Secret, 0, len(secrets))
	for _, secret := range secrets {
		if secret == nil {
			continue
		}
		if yieldsSymmetricKey(secret) {
			continue
		}
		kept = append(kept, secret)
	}
	return kept
}

func yieldsSymmetricKey(secret *storage_models.Secret) bool {
	keys := (&storage_models.Client{ClientSecrets: []*storage_models.Secret{secret}}).GetKeys()
	for i := 0; i < keys.Len(); i++ {
		key, ok := keys.Key(i)
		if ok && key.KeyType() == jwa.OctetSeq() {
			return true
		}
	}
	return false
}
