// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gonewx/wicket/auth"
	authcore "github.com/gonewx/wicket/auth/core"
	authevents "github.com/gonewx/wicket/auth/core/events"
	"github.com/gonewx/wicket/auth/oauth"
	claimspkg "github.com/gonewx/wicket/claims"
	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/utils"
)

type HandlerOverride interface {
	ExchangeCode(ctx *CodeExchangeContext) (*oauth.TokenResponse, error)
	CreateTicket(identity *claimspkg.ClaimsIdentity, properties *auth.Properties, tokens *oauth.TokenResponse) (*auth.Ticket, error)
	BuildChallengeUrl(properties *auth.Properties, redirectUri string) (string, error)
	FormatScope(scopes []string) string
}

type Handler[T oauth.Options[T]] struct {
	*authcore.RemoteHandler[T]
	override HandlerOverride
}

func NewHandler[T oauth.Options[T]](
	opts optspkg.OptionsMonitor[T],
	logger *slog.Logger,
	clock services.SystemClock,
) *Handler[T] {
	h := &Handler[T]{}

	h.RemoteHandler = authcore.NewRemoteHandler(opts, logger, clock, h, h).(*authcore.RemoteHandler[T])

	return h
}

func (h *Handler[T]) Override(override HandlerOverride) {
	h.override = override
}

func (h *Handler[T]) Events() *Events[T] {
	return h.Handler.Events.(*Events[T])
}

func (h *Handler[T]) SetEvents(e *Events[T]) {
	h.Handler.Events = e
}

// CreateEvents Creates a new instance of the events instance.
func (h *Handler[T]) CreateEvents() any {
	return NewEvents[T]()
}

func (h *Handler[T]) ClaimsIssuer() string {

	if h.Options.ClaimsIssuer() != "" {
		return h.Options.ClaimsIssuer()
	} else {
		return h.Scheme.Name
	}
}

func (h *Handler[T]) HandleRemoteAuthenticate() (*auth.HandleRequestResult, error) {
	query := h.Request().URL.Query()

	state := query.Get("state")
	properties := h.Options.StateDataFormat().Unprotect(state)

	if properties == nil {
		return auth.HandleRequestFail(fmt.Errorf("The oauth state was missing or invalid."), nil), nil
	}

	// OAuth2 10.12 CSRF
	ok, err := h.ValidateCorrelationId(properties)

	if err != nil {
		return nil, err
	}

	if !ok {
		return auth.HandleRequestFail(fmt.Errorf("Correlation failed."), properties), nil
	}

	error := query.Get("error")
	if strings.TrimSpace(error) != "" {
		// Note: access_denied errors are special protocol errors indicating the user didn't
		// approve the authorization demand requested by the remote authorization server.
		// Since it's a frequent scenario (that is not caused by incorrect configuration),
		// denied errors are handled differently using HandleAccessDeniedErrorAsync().
		// Visit https://tools.ietf.org/html/rfc6749#section-4.1.2.1 for more information.
		errorDescription := query.Get("error_description")
		errorUri := query.Get("error_uri")
		if error == "access_denied" {
			result, err := h.HandleAccessDeniedError(properties)
			if err != nil {
				return nil, err
			}
			if !result.None {
				return result, nil
			}

			deniedEx := fmt.Errorf("Access was denied by the resource owner or by the remote server. %s, %s, %s", error, errorDescription, errorUri)

			return auth.HandleRequestFail(deniedEx, properties), nil
		}

		failureMessage := strings.Builder{}
		failureMessage.WriteString(error)
		if errorDescription != "" {
			failureMessage.WriteString(";Description=")
			failureMessage.WriteString(errorDescription)
		}
		if errorUri != "" {
			failureMessage.WriteString(";Uri=")
			failureMessage.WriteString(errorUri)
		}
		ex := fmt.Errorf("%s", failureMessage.String())

		return auth.HandleRequestFail(ex, properties), nil
	}

	code := query.Get("code")

	if strings.TrimSpace(code) == "" {
		return auth.HandleRequestFail(fmt.Errorf("Code was not found."), properties), nil
	}

	codeExchangeContext := NewCodeExchangeContext(properties, code, h.BuildRedirectUri(h.Options.CallbackPath()))
	tokens, err := h.override.ExchangeCode(codeExchangeContext)
	if err != nil {
		return nil, err
	}

	if tokens.Error != nil {
		return auth.HandleRequestFail(tokens.Error, properties), nil
	}

	if strings.TrimSpace(tokens.AccessToken) == "" {
		return auth.HandleRequestFail(fmt.Errorf("Failed to retrieve access token."), properties), nil
	}

	identity := claimspkg.NewClaimsIdentity(
		claimspkg.WithAuthenticationType(h.ClaimsIssuer()),
	)

	if h.Options.SaveTokens() {
		authTokens := make([]*auth.Token, 0)
		authTokens = append(authTokens, &auth.Token{Name: "access_token", Value: tokens.AccessToken})
		if strings.TrimSpace(tokens.RefreshToken) != "" {
			authTokens = append(authTokens, &auth.Token{Name: "refresh_token", Value: tokens.RefreshToken})
		}

		if strings.TrimSpace(tokens.TokenType) != "" {
			authTokens = append(authTokens, &auth.Token{Name: "token_type", Value: tokens.TokenType})
		}

		if strings.TrimSpace(tokens.ExpiresIn) != "" {
			value, err := strconv.Atoi(tokens.ExpiresIn)
			if err != nil {
				return nil, err
			}
			// https://www.w3.org/TR/xmlschema-2/#dateTime
			// https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
			expiresAt := h.Clock.Now().Add(time.Duration(value) * time.Second)
			authTokens = append(authTokens, &auth.Token{Name: "expires_at", Value: expiresAt.Format(time.RFC3339)})
		}

		err = auth.StoreTokens(properties, authTokens)
		if err != nil {
			return nil, err
		}
	}

	ticket, err := h.override.CreateTicket(identity, properties, tokens)
	if err != nil {
		return nil, err
	}

	if ticket != nil {
		return auth.HandleRequestSuccess(ticket), nil
	}

	return auth.HandleRequestFail(fmt.Errorf("Failed to retrieve user information from remote server."), properties), nil
}

// ExchangeCode Exchanges the authorization code for a authorization token from the remote provider.
func (h *Handler[T]) ExchangeCode(ctx *CodeExchangeContext) (*oauth.TokenResponse, error) {
	tokenRequestParameters := url.Values{}
	tokenRequestParameters.Add("client_id", h.Options.ClientId())
	tokenRequestParameters.Add("redirect_uri", ctx.RedirectUri)
	tokenRequestParameters.Add("client_secret", h.Options.ClientSecret())
	tokenRequestParameters.Add("code", ctx.Code)
	tokenRequestParameters.Add("grant_type", "authorization_code")

	// PKCE https://tools.ietf.org/html/rfc7636#section-4.5, see BuildChallengeUrl
	codeVerifier := ctx.Properties.Items[oauth.CodeVerifierKey]
	if codeVerifier != "" {
		tokenRequestParameters.Add(oauth.CodeVerifierKey, codeVerifier)
		delete(ctx.Properties.Items, oauth.CodeVerifierKey)
	}

	requestMessage, err := http.NewRequest(http.MethodPost, h.Options.TokenEndpoint(), strings.NewReader(tokenRequestParameters.Encode()))
	if err != nil {
		return nil, err
	}

	requestMessage.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	requestMessage.Header.Set("Accept", "application/json")
	response, err := h.Options.Backchannel().Do(requestMessage)
	if err != nil {
		return nil, err
	}

	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return oauth.Success(string(body)), nil
	}

	reason, err := display(response)
	if err != nil {
		return nil, err
	}

	error := fmt.Errorf("OAuth token endpoint failure: %s", reason)
	return oauth.Failed(error), nil
}

func display(response *http.Response) (string, error) {
	output := strings.Builder{}
	output.WriteString("Status: ")
	output.WriteString(response.Status)
	output.WriteString(";Headers: ")

	for key, values := range response.Header {
		for _, value := range values {
			output.WriteString(key)
			output.WriteString(": ")
			output.WriteString(value)
			output.WriteString("\r\n")
		}
	}
	output.WriteString(";Body: ")
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	output.WriteString(string(body))
	output.WriteString(";")

	return output.String(), nil
}

// CreateTicket Creates an Ticket from the specified tokens.
func (h *Handler[T]) CreateTicket(identity *claimspkg.ClaimsIdentity, properties *auth.Properties, tokens *oauth.TokenResponse) (*auth.Ticket, error) {
	ctx, err := NewCreatingTicketContext(claimspkg.NewClaimsPrincipal(
		claimspkg.WithClaimsPrincipalIdentity(identity),
	), properties, h.Request(), h.Response(), h.Scheme, h.Options, h.Options.Backchannel(), tokens, "{}")
	if err != nil {
		return nil, err
	}

	_ = h.Events().CreatingTicket(ctx)

	return auth.NewTicket(ctx.Principal, h.Scheme.Name, ctx.Properties()), nil
}

func (h *Handler[T]) HandleChallenge(properties *auth.Properties) error {
	if properties.RedirectUri() == nil || strings.TrimSpace(*properties.RedirectUri()) == "" {
		redirectUri := h.OriginalPathBase() + h.OriginalPath() + h.Request().URL.Query().Encode()
		properties.SetRedirectUri(&redirectUri)
	}
	cookiet := h.Response().Header().Get("Set-Cookie")

	h.Logger.Debug("HandleChallenge show cookie.", slog.String("Cookie", cookiet))

	// OAuth2 10.12 CSRF
	_ = h.GenerateCorrelationId(properties)

	authorizationEndpoint, err := h.override.BuildChallengeUrl(properties, h.BuildRedirectUri(h.Options.CallbackPath()))
	if err != nil {
		return err
	}
	redirectContext := authevents.NewRedirectContext[T](h.Request(), h.Response(), h.Scheme, h.Options, properties, authorizationEndpoint)
	_ = h.Events().RedirectToAuthorizationEndpoint(redirectContext)

	location := h.Response().Header().Get("Location")
	if location == "" {
		location = "(not set)"
	}
	cookie := h.Response().Header().Get("Set-Cookie")
	if cookie == "" {
		cookie = "(not set)"
	}
	h.Logger.Debug("HandleChallenge with Location and Set-Cookie.", slog.String("Location", location), slog.String("Cookie", cookie))

	return nil
}

// BuildChallengeUrl Constructs the OAuth challenge url.
func (h *Handler[T]) BuildChallengeUrl(properties *auth.Properties, redirectUri string) (string, error) {
	scopeParameter, ok := properties.GetParameter(oauth.ScopeKey).([]string)
	if !ok {
		scopeParameter = nil
	}

	scope := ""

	if scopeParameter != nil {
		scope = h.override.FormatScope(scopeParameter)
	} else {
		scopes := make([]string, len(h.Options.Scope()))
		for i, s := range h.Options.Scope() {
			scopes[i] = s
		}

		scope = h.override.FormatScope(scopes)
	}

	authorizationEndpoint := h.Options.AuthorizationEndpoint()
	ep, err := url.Parse(authorizationEndpoint)
	if err != nil {
		return "", err
	}
	parameters := ep.Query()
	parameters.Add("client_id", h.Options.ClientId())
	parameters.Add("scope", scope)
	parameters.Add("response_type", "code")
	parameters.Add("redirect_uri", redirectUri)

	if h.Options.UsePkce() {
		bytes, err := utils.CreateRandomKey(32)
		if err != nil {
			return "", err
		}

		codeVerifier := base64.RawURLEncoding.EncodeToString(bytes)

		// Store this for use during the code redemption.
		properties.Items[oauth.CodeVerifierKey] = codeVerifier

		h := sha256.New()
		h.Write(bytes)
		challengeBytes := h.Sum(nil)
		codeChallenge := base64.RawURLEncoding.EncodeToString(challengeBytes)

		parameters[oauth.CodeChallengeKey] = []string{codeChallenge}
		parameters[oauth.CodeChallengeMethodKey] = []string{oauth.CodeChallengeMethodS256}
	}

	parameters["state"] = []string{h.Options.StateDataFormat().Protect(properties)}

	ep.RawQuery = parameters.Encode()

	return ep.String(), nil
}

// FormatScope Format a list of OAuth scopes.
func (h *Handler[T]) FormatScope(scopes []string) string {
	// OAuth2 3.3 space separated
	return strings.Join(scopes, " ")
}
