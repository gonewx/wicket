// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package messages

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/utils"
)

// ConsentRequest Models the parameters to identify a request for consent.
type ConsentRequest struct {
	/// Gets or sets the client identifier.
	/// The client identifier.
	ClientId string

	/// Gets or sets the nonce.
	/// The nonce.
	Nonce string

	/// Gets or sets the scopes requested.
	/// The scopes requested.
	ScopesRequested []string

	/// Gets or sets the subject.
	/// The subject.
	Subject string
}

func WithConsentRequestAuthorizationRequest(request *AuthorizationRequest) gois.Option[ConsentRequest] {
	return func(r *ConsentRequest) {
		r.ClientId = request.Client.ClientId
		r.Nonce = request.Parameters.Get(gois.AuthorizeRequestNonce)
		r.ScopesRequested = utils.ParseScopesString(request.Parameters.Get(gois.AuthorizeRequestScope))
	}
}

func WithConsentRequestParameters(parameters url.Values) gois.Option[ConsentRequest] {
	return func(r *ConsentRequest) {
		r.ClientId = parameters.Get(gois.AuthorizeRequestClientId)
		r.Nonce = parameters.Get(gois.AuthorizeRequestNonce)
		r.ScopesRequested = utils.ParseScopesString(parameters.Get(gois.AuthorizeRequestScope))
	}
}

// / Initializes a new instance of the <see cref="ConsentRequest"/> class.
// / <param name="request">The request.</param>
// / <param name="subject">The subject.</param>
func NewConsentRequest(subject string, opts ...gois.Option[ConsentRequest]) *ConsentRequest {
	r := &ConsentRequest{}
	for _, o := range opts {
		o(r)
	}
	r.Subject = subject

	return r
}

// / Gets the identifier.
// / The identifier.
func (r *ConsentRequest) Id() string {
	sort.Strings(r.ScopesRequested)
	normalizedScopes := utils.Aggregate(
		utils.Distinct(r.ScopesRequested), func(x, y string) string {
			return x + "," + y
		})

	var value = fmt.Sprintf("%s:%s:%s:%s", r.ClientId, r.Subject, r.Nonce, normalizedScopes)

	h := sha256.New()
	h.Write([]byte(value))

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
