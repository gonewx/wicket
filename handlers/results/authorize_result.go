// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/models/messages"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
)

type AuthorizeResult struct {
	Response *responses_models.AuthorizeResponse

	options           *config_options.WicketOptions
	userSession       services.UserSession
	errorMessageStore storage.MessageStore[messages.ErrorMessage]
	urls              services.ServerUrls
	clock             services.SystemClock
}

func NewAuthorizeResult(
	response *responses_models.AuthorizeResponse,
) *AuthorizeResult {
	return &AuthorizeResult{
		Response: response,
	}
}

func newAuthorizeResult(
	response *responses_models.AuthorizeResponse,
	options *config_options.WicketOptions,
	userSession services.UserSession,
	errorMessageStore storage.MessageStore[messages.ErrorMessage],
	urls services.ServerUrls,
	clock services.SystemClock,
) *AuthorizeResult {
	return &AuthorizeResult{
		Response:          response,
		options:           options,
		userSession:       userSession,
		errorMessageStore: errorMessageStore,
		urls:              urls,
		clock:             clock,
	}
}

func (ar *AuthorizeResult) init(ctx context.Context) {
	if ar.options == nil {
		// AD-10: AuthorizeResult resolves options from RequestServices.
		ar.options = godi.GetRequired[*config_options.WicketOptions](hosting.ScopeFrom(ctx))
	}

	if ar.userSession == nil {
		// AD-10: AuthorizeResult resolves UserSession from RequestServices.
		ar.userSession = godi.GetRequired[services.UserSession](hosting.ScopeFrom(ctx))
	}

	if ar.errorMessageStore == nil {
		// AD-10: AuthorizeResult resolves message stores from RequestServices.
		ar.errorMessageStore = godi.GetRequired[storage.MessageStore[messages.ErrorMessage]](hosting.ScopeFrom(ctx))
	}

	if ar.urls == nil {
		// AD-10: AuthorizeResult resolves ServerUrls from RequestServices.
		ar.urls = godi.GetRequired[services.ServerUrls](hosting.ScopeFrom(ctx))
	}

	if ar.clock == nil {
		// AD-10: AuthorizeResult resolves SystemClock from RequestServices.
		ar.clock = godi.GetRequired[services.SystemClock](hosting.ScopeFrom(ctx))
	}
}

func (ar *AuthorizeResult) Execute(w http.ResponseWriter, r *http.Request) error {
	ar.init(r.Context())

	if ar.Response.Error != nil {
		return ar.processError(w, r)
	}

	return ar.ProcessResponse(w, r)
}

func (ar *AuthorizeResult) processError(w http.ResponseWriter, r *http.Request) error {
	// these are the conditions where we can send a response
	// back directly to the client, otherwise we're only showing the error UI
	if isSafeError(ar.Response.Error) {
		// this scenario we can return back to the client
		return ar.ProcessResponse(w, r)
	} else {
		// we now know we must show error page
		return ar.RedirectToErrorPage(w, r)
	}
}

func (ar *AuthorizeResult) ToQueryValues(options *config_options.WicketOptions) url.Values {
	values := url.Values{}
	if ar.Response.Error != nil {
		values.Set("error", ar.Response.Error.Error())
		if ar.Response.ErrorDescription != "" {
			values.Set("error_description", ar.Response.ErrorDescription)
		}
	} else {
		if ar.Response.Code != "" {
			values.Set("code", ar.Response.Code)
		}

		if ar.Response.IdentityToken != "" {
			values.Set("id_token", ar.Response.IdentityToken)
		}

		if ar.Response.AccessToken != "" {
			values.Set("access_token", ar.Response.AccessToken)
			values.Set("token_type", "Bearer")
			values.Set("expires_in", strconv.Itoa(ar.Response.AccessTokenLifetime))
		}
		if ar.Response.Scope() != "" {
			values.Set("scope", ar.Response.Scope())
		}

	}

	if ar.Response.State() != "" {
		values.Set("state", ar.Response.State())
	}
	if ar.Response.SessionState != "" {
		values.Set("session_state", ar.Response.SessionState)
	}
	if ar.Response.Issuer != "" {
		if ar.options.EmitIssuerIdentificationResponseParameter {
			values.Set("iss", ar.Response.Issuer)
		}
	}

	return values
}

func (ar *AuthorizeResult) ProcessResponse(w http.ResponseWriter, r *http.Request) error {
	if ar.Response.Error == nil && ar.Response.Request != nil {
		// success response -- track client authorization for sign-out
		if err := ar.userSession.AddClientId(ar.Response.Request.ClientId); err != nil {
			ar.Response.Error = err
			return ar.RedirectToErrorPage(w, r)
		}
	}

	return ar.renderAuthorizeResponse(w, r)
}

func (ar *AuthorizeResult) renderAuthorizeResponse(w http.ResponseWriter, r *http.Request) error {
	req := ar.Response.Request

	if req == nil {
		return gois.ArgumentNullException
	}

	if req.ResponseMode == gois.ResponseModesQuery || req.ResponseMode == gois.ResponseModesFragment {
		HttpRespSetNoCache(w)
		redirectUri := ar.buildRedirectUri()
		http.Redirect(w, r, redirectUri, http.StatusFound)
	} else {
		if req.ResponseMode == gois.ResponseModesFormPost {
			HttpRespSetNoCache(w)
			// the hash matches the inline submit script embedded in formPostHtml below
			AddScriptCspHeaders(w, ar.options.Csp, "sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8=")

			if err := HttpRespWriteHtml(w, []byte(ar.GetFormPostHtml()), ""); err != nil {
				return err
			}

		} else {
			return gois.InvalidOperationException
		}
	}

	return nil
}

func (ar *AuthorizeResult) RedirectToErrorPage(w http.ResponseWriter, r *http.Request) error {
	errorModel := messages.NewErrorMessage()
	//TODO:
	// errorModel.RequestId = context.TraceIdentifier
	errorModel.Error = ar.Response.Error.Error()
	errorModel.ErrorDescription = ar.Response.ErrorDescription

	if ar.Response.Request != nil {
		errorModel.UiLocales = ar.Response.Request.UiLocales
		errorModel.DisplayMode = ar.Response.Request.DisplayMode
		errorModel.ClientId = ar.Response.Request.ClientId

		if ar.Response.RedirectUri() != "" && ar.Response.Request.ResponseMode != "" {
			errorModel.RedirectUri = ar.buildRedirectUri()
			errorModel.ResponseMode = ar.Response.Request.ResponseMode
		}

	}

	errorUrl := ar.options.UserInteraction.ErrorUrl

	if utils.IsLocalUrl(errorUrl) {
		errorUrl = ar.urls.GetWicketRelativeUrl(errorUrl)
	}

	message := messages.NewMessageWithCreated(errorModel, time.Now().Unix())
	id, err := ar.errorMessageStore.Write(message)
	if err != nil {
		return err
	}

	url, err := url.Parse(errorUrl)
	if err != nil {
		return err
	}
	values := url.Query()
	values.Add(ar.options.UserInteraction.ErrorIdParameter, id)

	url.RawQuery = values.Encode()

	// http.Redirect(w, r, url.String(), http.StatusFound)
	http.Redirect(w, r, utils.GetAbsoluteUrl(ar.urls.BaseUrl(), url.String()), http.StatusFound)
	return nil
}

func (ar *AuthorizeResult) buildRedirectUri() string {

	uri := ar.Response.RedirectUri()

	query := ar.ToQueryValues(ar.options).Encode()

	if ar.Response.Request.ResponseMode == gois.ResponseModesQuery {
		uri = utils.AddQueryString(uri, query)
	} else {
		uri = utils.AddHashFragment(uri, query)
	}

	if ar.Response.Error != nil && !strings.Contains(uri, "#") {
		// https://tools.ietf.org/html/draft-bradley-oauth-open-redirector-00
		uri = uri + "#_=_"
	}

	return uri
}

func isSafeError(err error) bool {
	if errors.Is(err, gois.AuthorizeErrorsAccessDenied) ||
		errors.Is(err, gois.AuthorizeErrorsAccountSelectionRequired) ||
		errors.Is(err, gois.AuthorizeErrorsLoginRequired) ||
		errors.Is(err, gois.AuthorizeErrorsConsentRequired) ||
		errors.Is(err, gois.AuthorizeErrorsInteractionRequired) ||
		errors.Is(err, gois.AuthorizeErrorsTemporarilyUnavailable) {
		return true
	}

	return false
}

func ToFormPost(values url.Values) string {
	var sb strings.Builder
	for k, value := range values {
		v := ""
		if len(value) > 0 {
			v = html.EscapeString(value[0])
		}
		sb.WriteString(fmt.Sprintf("<input type='hidden' name='%s' value='%s' />\n", k, v))
	}
	return sb.String()
}

const (
	formPostHtml = "<html><head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head><body><form method='post' action='{{ .uri }}'>{{ .body }}<noscript><button>Click to continue</button></noscript></form><script>window.addEventListener('load', function(){document.forms[0].submit();});</script></body></html>"
)

func (ar *AuthorizeResult) GetFormPostHtml() string {
	html := formPostHtml

	url, err := url.Parse(ar.Response.Request.RedirectUri)
	if err != nil {
		return ""
	}

	t, err := template.New("FormPost").Parse(html)
	if err != nil {
		return ""
	}

	var b bytes.Buffer
	uri := url.String()
	body := ToFormPost(ar.ToQueryValues(ar.options))
	err = t.Execute(&b, map[string]string{
		"uri":  uri,
		"body": body,
	})
	if err != nil {
		return ""
	}
	return b.String()
}
