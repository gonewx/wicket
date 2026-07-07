// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/utils"
)

type ValidatedAuthorizeRequest struct {
	*ValidatedRequest
	ResponseType                          string
	ResponseMode                          string
	GrantType                             string
	RedirectUri                           string
	RequestedScopes                       []string
	RequestedResourceIndiators            []string
	WasConsentShown                       bool
	Description                           string
	State                                 string
	UiLocales                             string
	IsOpenIdRequest                       bool
	IsApiResourceRequest                  bool
	Nonce                                 string
	AuthenticationContextReferenceClasses []string
	DisplayMode                           string
	PromptModes                           []string
	OriginalPromptModes                   []string
	SuppressedPromptModes                 []string
	MaxAge                                int
	LoginHint                             string
	CodeChallenge                         string
	CodeChallengeMethod                   string
	RequestObjectValues                   []*claims.Claim
	RequestObject                         string
}

func NewValidatedAuthorizeRequest() *ValidatedAuthorizeRequest {
	return &ValidatedAuthorizeRequest{
		ValidatedRequest: NewValidatedRequest(),
	}
}

func (r *ValidatedAuthorizeRequest) RemovePrompt() {
	var suppress strings.Builder
	if utils.Contains(r.PromptModes, gois.PromptModesLogin) {
		suppress.WriteString(gois.PromptModesLogin)
	}

	if utils.Contains(r.PromptModes, gois.PromptModesSelectAccount) {
		if suppress.Len() > 0 {
			suppress.WriteString(" ")
		}
		suppress.WriteString(gois.PromptModesSelectAccount)
	}

	r.Raw.Add(gois.SuppressedPrompt, suppress.String())
	r.PromptModes = utils.Except(r.PromptModes, []string{gois.PromptModesLogin, gois.PromptModesSelectAccount})
}

func (r *ValidatedAuthorizeRequest) AccessTokenRequested() bool {
	return r.ResponseType == gois.ResponseTypesIdTokenToken ||
		r.ResponseType == gois.ResponseTypesCode ||
		r.ResponseType == gois.ResponseTypesCodeIdToken ||
		r.ResponseType == gois.ResponseTypesCodeToken ||
		r.ResponseType == gois.ResponseTypesCodeIdTokenToken
}

func (r *ValidatedAuthorizeRequest) ToOptimizedRawValues() url.Values {
	if _, ok := r.Raw[gois.AuthorizeRequestRequest]; ok {
		// if we already have a request object in the URL, then we can filter out the duplicate entries in the Raw collection
		values := make(url.Values, 0)
		for key, value := range r.Raw {
			// https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
			// requires client id and response type to always be in URL
			if key == gois.AuthorizeRequestClientId ||
				key == gois.AuthorizeRequestResponseType ||
				utils.All(r.RequestObjectValues, func(x *claims.Claim) bool {
					return x.Type != key
				}) {
				values[key] = append(values[key], value...)
			}
		}
		return values
	}

	return r.Raw
}

func (r *ValidatedAuthorizeRequest) GetPrefixedAcrValue(prefix string) string {
	value := utils.FirstOrDefaultPred(r.AuthenticationContextReferenceClasses, func(x string) bool {
		return strings.HasPrefix(x, prefix)
	})
	if value != "" {
		value = strings.TrimPrefix(value, prefix)
	}

	return value
}

func (r *ValidatedAuthorizeRequest) GetIdP() string {
	return r.GetPrefixedAcrValue(gois.KnownAcrValuesHomeRealm)
}

func (r *ValidatedAuthorizeRequest) RemovePrefixedAcrValue(prefix string) {
	r.AuthenticationContextReferenceClasses = utils.SkipWhile(r.AuthenticationContextReferenceClasses, func(x string) bool {
		return strings.HasPrefix(x, prefix)
	})

	acrValues := utils.ToSpaceSeparatedString(r.AuthenticationContextReferenceClasses)
	if acrValues != "" {
		r.Raw.Set(gois.AuthorizeRequestAcrValues, acrValues)
	} else {
		r.Raw.Del(gois.AuthorizeRequestAcrValues)
	}
}

func (r *ValidatedAuthorizeRequest) RemoveIdP() {
	r.RemovePrefixedAcrValue(gois.KnownAcrValuesHomeRealm)
}

func (r *ValidatedAuthorizeRequest) GetTenant() string {
	return r.GetPrefixedAcrValue(gois.KnownAcrValuesTenant)
}

func (r *ValidatedAuthorizeRequest) GenerateSessionStateValue() string {
	if !r.IsOpenIdRequest {
		return ""
	}

	if r.SessionId == "" {
		return ""
	}

	if strings.TrimSpace(r.ClientId) == "" {
		return ""
	}

	if strings.TrimSpace(r.RedirectUri) == "" {
		return ""
	}

	clientId := r.ClientId
	sessionId := r.SessionId

	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return ""
	}

	uri, err := url.Parse(r.RedirectUri)
	if err != nil {
		return ""
	}
	origin := uri.Scheme + "://" + uri.Host

	b := []byte(clientId + origin + sessionId)
	b = append(b, salt...)

	h := sha256.New()
	h.Write(b)

	return base64.URLEncoding.EncodeToString(h.Sum(nil)) + "." + strings.ToUpper(hex.EncodeToString(salt))
}

func (r *ValidatedAuthorizeRequest) GetAcrValues() []string {
	return utils.Distinct(
		utils.Where(r.AuthenticationContextReferenceClasses, func(acr string) bool {
			return !utils.AnyPred(gois.KnownAcrValuesAll, func(wellKnown string) bool {
				return strings.HasPrefix(acr, wellKnown)
			})
		}))
}
