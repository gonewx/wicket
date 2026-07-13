// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package google

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/auth/oauth"
	oauthcore "github.com/gonewx/wicket/auth/oauth/core"
	claimspkg "github.com/gonewx/wicket/claims"
	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/gonewx/wicket/services"
)

type Handler struct {
	*oauthcore.Handler[*Options]
}

func NewHandler(
	opts optspkg.OptionsMonitor[*Options],
	logger *slog.Logger,
	clock services.SystemClock,
) *Handler {
	h := &Handler{}
	h.Handler = oauthcore.NewHandler[*Options](opts, logger, clock)
	h.Handler.Override(h)
	return h
}

func (h *Handler) CreateTicket(identity *claimspkg.ClaimsIdentity, properties *auth.Properties, tokens *oauth.TokenResponse) (*auth.Ticket, error) {
	req, err := http.NewRequest(http.MethodGet, UserInformationEndpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	resp, err := h.Options.Backchannel().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("An error occurred when retrieving Google user information %d. Please check if the authentication information is correct.", resp.StatusCode)
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	ctx, err := oauthcore.NewCreatingTicketContext(claimspkg.NewClaimsPrincipal(
		claimspkg.WithClaimsPrincipalIdentity(identity),
	), properties, h.Request(), h.Response(), h.Scheme, h.Options, h.Options.Backchannel(), tokens, string(payload))
	if err != nil {
		return nil, err
	}
	ctx.RunClaimActions()
	_ = h.Events().CreatingTicket(ctx)

	return auth.NewTicket(ctx.Principal, h.Scheme.Name, ctx.Properties()), nil
}

func (h *Handler) BuildChallengeUrl(properties *auth.Properties, redirectUri string) (string, error) {
	authorizationEndpoint := h.Options.AuthorizationEndpoint()

	ep, err := url.Parse(authorizationEndpoint)
	if err != nil {
		return "", err
	}

	parameters := ep.Query()
	parameters.Add("response_type", "code")
	parameters.Add("client_id", h.Options.ClientId())
	parameters.Add("redirect_uri", redirectUri)

	scope := h.Options.Scope()
	addQueryStringWithFormatter(parameters, properties, oauth.ScopeKey, h.formatScope, &scope)

	addQueryString(parameters, properties, AccessTypeKey, h.Options.AccessType)

	addQueryString[string](parameters, properties, ApprovalPromptKey, nil)
	addQueryString[string](parameters, properties, PromptParameterKey, nil)
	addQueryString[string](parameters, properties, LoginHintKey, nil)

	addQueryStringWithFormatter(parameters, properties, IncludeGrantedScopesKey, func(v bool) *string {
		var result string
		if v {
			result = "true"
		} else {
			result = "false"
		}
		return &result
	}, nil)

	parameters["state"] = []string{h.Options.StateDataFormat().Protect(properties)}

	ep.RawQuery = parameters.Encode()

	return ep.String(), nil
}

func addQueryStringWithFormatter[T any](queryStrings url.Values, properties *auth.Properties, name string, formatter func(T) *string, defaultValue *T) {
	var value *string
	parameterValue, ok := properties.GetParameter(name).(T)
	if ok {
		value = formatter(parameterValue)
	} else {
		if v, ok := properties.Items[name]; !ok {
			if defaultValue != nil {
				value = formatter(*defaultValue)
			}
		} else {
			value = &v
		}
	}

	delete(properties.Items, name)

	if value != nil {
		queryStrings[name] = []string{*value}
	}
}

func addQueryString[T any](queryStrings url.Values, properties *auth.Properties, name string, defaultValue *T) {
	addQueryStringWithFormatter[T](queryStrings, properties, name, func(v T) *string {
		result := fmt.Sprintf("%v", v)
		return &result
	}, defaultValue)
}

func (h *Handler) formatScope(scope []string) *string {
	r := h.Handler.FormatScope(scope)
	return &r
}
