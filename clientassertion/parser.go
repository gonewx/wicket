// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"encoding/base64"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/validators"
)

// Parser finds a client assertion among the form parameters of a request. It
// neither verifies the assertion nor looks anything up; it only names the
// party the assertion claims to come from so the authenticator can load it.
type Parser struct {
	options           Options
	maxIdentityLength int
}

var _ validators.SecretParser = (*Parser)(nil)

// NewParser returns a parser for the given options. maxIdentityLength bounds
// the length of the identity the parser reports; zero or less treats every
// identity as too long, so the parser reports none.
func NewParser(options Options, maxIdentityLength int) *Parser {
	return &Parser{options: options.withDefaults(), maxIdentityLength: maxIdentityLength}
}

// AuthenticationMethod returns "private_key_jwt".
func (p *Parser) AuthenticationMethod() string {
	return authenticationMethod
}

// SigningAlgorithms returns the accepted signature algorithms in configured
// order.
func (p *Parser) SigningAlgorithms() []string {
	return slices.Clone(p.options.SigningAlgorithms)
}

// Parse returns nil when the request carries no assertion parameter.
// Otherwise it returns a parsed secret of the assertion type whose Id is the
// assertion's unverified subject, or the form client_id when the subject
// cannot be read, and whose Credential is the assertion. It never fails.
func (p *Parser) Parse(request *http.Request) (*models.ParsedSecret, error) {
	form := assertionForm(request)
	if form == nil {
		return nil, nil
	}
	kind := form.Get("client_assertion_type")
	assertion := form.Get("client_assertion")
	if kind == "" && assertion == "" {
		return nil, nil
	}
	secret := &models.ParsedSecret{Type: wicket.ParsedSecretTypesJwtBearer}
	if len(assertion) > p.options.MaxAssertionBytes {
		secret.Id = p.usableIdentity(form.Get("client_id"))
		return secret, nil
	}
	secret.Credential = assertion
	secret.Id = p.usableIdentity(unverifiedSubject(assertion))
	if secret.Id == "" {
		secret.Id = p.usableIdentity(form.Get("client_id"))
	}
	return secret, nil
}

// usableIdentity returns id when it can serve as a lookup identity, or "".
func (p *Parser) usableIdentity(id string) string {
	if id == "" || len(id) > p.maxIdentityLength {
		return ""
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x20 || id[i] == 0x7f {
			return ""
		}
	}
	return id
}

// assertionForm returns the body parameters of a form encoded request, or nil
// for any other request.
func assertionForm(request *http.Request) url.Values {
	if request == nil {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil
	}
	if request.PostForm == nil {
		if err := request.ParseForm(); err != nil {
			return nil
		}
	}
	return request.PostForm
}

// hasBasicAuthorization reports whether the request carries HTTP Basic
// credentials.
func hasBasicAuthorization(request *http.Request) bool {
	header := request.Header.Get("Authorization")
	return len(header) >= 6 && strings.EqualFold(header[:6], "Basic ")
}

// unverifiedSubject reads the sub claim of a compact assertion without
// checking anything else. It returns "" when the claim cannot be read.
func unverifiedSubject(assertion string) string {
	segments := strings.Split(assertion, ".")
	if len(segments) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Subject json.RawMessage `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	var subject string
	if err := json.Unmarshal(claims.Subject, &subject); err != nil {
		return ""
	}
	return subject
}
