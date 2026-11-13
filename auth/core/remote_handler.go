// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	authevents "github.com/gonewx/wicket/auth/core/events"
	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/utils"
)

const (
	CorrelationProperty = ".xsrf"
	CorrelationMarker   = "N"
	AuthSchemeKey       = ".AuthScheme"
)

var _ auth.RequestHandler = (*RemoteHandler[*RemoteOptions])(nil)

type RemoteHandler[T auth.RemoteOptions[T]] struct {
	*Handler[T]

	remoteOverride auth.RemoteHandlerOverride
	// correlationCookieBuilder *Builder
}

func NewRemoteHandler[T auth.RemoteOptions[T]](
	opts optspkg.OptionsMonitor[T],
	logger *slog.Logger,
	clock services.SystemClock,
	override auth.HandlerOverride,
	remoteOverride auth.RemoteHandlerOverride,
) auth.Handler {
	h := &RemoteHandler[T]{}
	h.Handler = NewHandler(opts, logger, clock, override).(*Handler[T])

	h.remoteOverride = remoteOverride

	return h
}

// SignInScheme The authentication scheme used by default for signin.
func (h *RemoteHandler[T]) SignInScheme() string {
	return h.Options.SignInScheme()
}

func (h *RemoteHandler[T]) Events() authevents.RemoteEvents[T] {
	return h.Handler.Events.(authevents.RemoteEvents[T])
}

func (h *RemoteHandler[T]) SetEvents(value any) {
	h.Handler.Events = value
}

func (h *RemoteHandler[T]) CreateEvents() any {
	if h.remoteOverride != nil {
		return h.remoteOverride.CreateEvents()
	}
	return NewRemoteEvents[T]()
}

// ShouldHandleRequest Gets a value that determines if the current authentication request should be handled by HandleRequestAsync.
func (h *RemoteHandler[T]) ShouldHandleRequest() bool {
	return h.Options.CallbackPath() == h.Request().URL.Path
}

// / Handles the current authentication request.
func (h *RemoteHandler[T]) HandleRequest() (bool, error) {
	if !h.ShouldHandleRequest() {
		return false, nil
	}

	var ticket *auth.Ticket
	var err error
	var properties *auth.Properties
	authResult, err := h.remoteOverride.HandleRemoteAuthenticate()
	if err != nil || authResult == nil {
		if err != nil {
			// 保留 HandleRemoteAuthenticate 返回的真实失败原因（例如后端换取 token
			// 失败、correlation 读取异常等），避免被下面的通用消息掩盖导致无法定位根因。
			err = fmt.Errorf("Invalid return state, unable to redirect: %w. %w", err, wicket.InvalidOperationException)
		} else {
			err = fmt.Errorf("Invalid return state, unable to redirect. %w", wicket.InvalidOperationException)
		}
	} else {
		if authResult.Handled {
			return true, nil
		} else {
			if authResult.Skipped || authResult.None {
				return false, nil
			} else {
				if !authResult.Succeeded() {
					err = authResult.Failure
					if err == nil {
						err = fmt.Errorf("Invalid return state, unable to redirect. %w", wicket.InvalidOperationException)
					}
					properties = authResult.Properties
				}
			}
		}
		ticket = authResult.Ticket
	}

	if err != nil {
		h.Logger.Info("Error from RemoteAuthentication", slog.String("error", err.Error()))
		errorContext := authevents.NewRemoteFailureContext(h.Request(), h.Response(), h.Scheme, h.Options, err)
		errorContext.Properties = properties
		_ = h.Events().RemoteFailure(errorContext)

		if errorContext.Result != nil {
			if errorContext.Result.Handled {
				return true, nil
			} else {
				if errorContext.Result.Skipped {
					return false, nil
				} else {
					if errorContext.Result.Failure != nil {
						err = fmt.Errorf("An error was returned from the RemoteFailure event. %w", errorContext.Result.Failure)
						return false, err
					}
				}
			}
		}

		if errorContext.Failure != nil {
			return false, fmt.Errorf("An error was encountered while handling the remote login. %w", errorContext.Failure)
		}

	}

	// We have a ticket if we get here
	ticketContext := authevents.NewTicketReceivedContext(h.Request(), h.Response(), h.Scheme, h.Options, ticket)

	returnUri := ticket.Properties.RedirectUri()

	if returnUri != nil {
		ticketContext.ReturnUri = *returnUri
	}

	ticket.Properties.SetRedirectUri(nil)

	// Mark which provider produced this identity so we can cross-check later in HandleAuthenticateAsync
	ticket.Properties.Items[AuthSchemeKey] = h.Scheme.Name

	_ = h.Events().TicketReceived(ticketContext)

	if ticketContext.Result != nil {
		if ticketContext.Result.Handled {
			h.Logger.Debug("The SigningIn event returned Handled.")
			return true, nil
		} else {
			if ticketContext.Result.Skipped {
				h.Logger.Debug("The SigningIn event returned Skipped.")
				return false, nil
			}
		}
	}

	svc, err := service(h.Request().Context())
	if err != nil {
		return false, err
	}

	if err := svc.SignIn(h.Request(), h.Response(), h.SignInScheme(), ticketContext.Principal, ticketContext.Properties); err != nil {
		return false, err
	}

	// Default redirect path is the base path
	if strings.TrimSpace(ticketContext.ReturnUri) == "" {
		ticketContext.ReturnUri = "/"
	}

	http.Redirect(h.Response(), h.Request(), ticketContext.ReturnUri, http.StatusFound)
	return true, nil
}

func (h *RemoteHandler[T]) HandleAuthenticate() (*auth.Result, error) {
	svc, err := service(h.Request().Context())
	if err != nil {
		return nil, err
	}

	result, err := svc.Authenticate(h.Request(), h.Response(), h.SignInScheme())
	if err != nil {
		return nil, err
	}

	fail := auth.Fail(fmt.Errorf("Remote authentication does not directly support AuthenticateAsync"))

	if result == nil {
		return fail, nil
	}

	if result.Failure != nil {
		return result, nil
	}

	// The SignInScheme may be shared with multiple providers, make sure this provider issued the identity.
	ticket := result.Ticket
	if ticket != nil &&
		ticket.Principal != nil &&
		ticket.Properties != nil &&
		ticket.Properties.Items[AuthSchemeKey] == h.Scheme.Name {

		return auth.Success(
			auth.NewTicket(ticket.Principal, h.Scheme.Name, ticket.Properties),
		), nil
	}

	return fail, nil
}

func (h *RemoteHandler[T]) HandleForbidden(properties *auth.Properties) error {
	svc, err := service(h.Request().Context())
	if err != nil {
		return err
	}

	return svc.Forbid(h.Request(), h.Response(), h.Scheme.Name, nil)
}

// generateCorrelationId Produces a cookie containing a nonce used to correlate the current remote authentication request.
func (h *RemoteHandler[T]) GenerateCorrelationId(properties *auth.Properties) error {
	if properties == nil {
		return wicket.ArgumentNullException
	}

	bytes, err := utils.CreateRandomKey(32)
	if err != nil {
		return err
	}

	correlationId := base64.RawURLEncoding.EncodeToString(bytes)

	// Stamp the correlation cookie through the injected clock. Options are cloned
	// per request by the monitor, so the clock is set at the use site rather than
	// once at construction.
	h.Options.CorrelationCookie().SetClock(h.Clock)
	cookieOptions := h.Options.CorrelationCookie().Build(h.Request())

	properties.Items[CorrelationProperty] = correlationId

	cookieName := h.Options.CorrelationCookie().Name() + correlationId

	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    CorrelationMarker,
		Domain:   cookieOptions.Domain,
		Path:     cookieOptions.Path,
		HttpOnly: cookieOptions.HttpOnly,
		Secure:   cookieOptions.Secure,
		SameSite: cookieOptions.SameSite,
	}
	if cookieOptions.Expires != nil {
		cookie.Expires = *cookieOptions.Expires
	}

	if cookieOptions.MaxAge != nil {
		cookie.MaxAge = int(cookieOptions.MaxAge.Seconds())
	}
	http.SetCookie(h.Response(), cookie)

	return nil
}

// validateCorrelationId Validates that the current request correlates wit hthe
func (h *RemoteHandler[T]) ValidateCorrelationId(properties *auth.Properties) (bool, error) {
	if properties == nil {
		return false, wicket.ArgumentNullException
	}

	correlationId := properties.Items[CorrelationProperty]
	if correlationId == "" {
		h.Logger.Warn("CorrelationProperty state property not found.", slog.String("CorrelationProperty", h.Options.CorrelationCookie().Name()))
		return false, nil
	}

	delete(properties.Items, CorrelationProperty)

	cookieName := h.Options.CorrelationCookie().Name() + correlationId

	correlationCookie, err := h.Request().Cookie(cookieName)
	if err != nil {
		// 未找到 correlation cookie（http.ErrNoCookie）属于 correlation 校验失败，
		// 应作为 "Correlation failed." 返回，而不是当成系统级错误向上抛，
		// 与 ASP.NET Core RemoteAuthenticationHandler 的行为保持一致。
		h.Logger.Warn("Correlation cookie not found.", slog.String("CorrelationCookieName", cookieName))
		return false, nil
	}

	if strings.TrimSpace(correlationCookie.Value) == "" {
		h.Logger.Warn("CorrelationProperty state property not found.", slog.String("CorrelationProperty", h.Options.CorrelationCookie().Name()))
		return false, nil
	}

	// Stamp the correlation cookie through the injected clock (see
	// GenerateCorrelationId — set at the use site to survive per-request cloning).
	h.Options.CorrelationCookie().SetClock(h.Clock)
	cookieOptions := h.Options.CorrelationCookie().Build(h.Request())
	cookie := &http.Cookie{
		Name:     cookieName,
		Path:     cookieOptions.Path,
		Domain:   cookieOptions.Domain,
		SameSite: cookieOptions.SameSite,
		Secure:   cookieOptions.Secure,
		Expires:  time.Unix(0, 0),
		HttpOnly: cookieOptions.HttpOnly,
	}
	http.SetCookie(h.Response(), cookie)

	if correlationCookie.Value != CorrelationMarker {
		h.Logger.Warn("The correlation cookie value did not match the expected value.", slog.String("CorrelationCookieName", cookieName), slog.String("CorrelationCookieValue", correlationCookie.Value))
		return false, nil
	}

	return true, nil
}

// / Derived types may override this method to handle access denied errors.
func (h *RemoteHandler[T]) HandleAccessDeniedError(properties *auth.Properties) (*auth.HandleRequestResult, error) {
	h.Logger.Info("Access was denied by the resource owner or by the remote server.")

	ctx := authevents.NewAccessDeniedContext(h.Request(), h.Response(), h.Scheme, h.Options)
	ctx.AccessDeniedPath = h.Options.AccessDeniedPath()
	ctx.Properties = properties

	if properties.RedirectUri() != nil {
		ctx.ReturnUrl = *properties.RedirectUri()
	}

	ctx.ReturnUrlParameter = h.Options.ReturnUrlParameter()

	_ = h.Events().AccessDenied(ctx)

	if ctx.Result != nil {
		if ctx.Result.Handled {
			h.Logger.Debug("The AccessDenied event returned Handled.")
		} else {
			if ctx.Result.Skipped {
				h.Logger.Debug("The AccessDenied event returned Skipped.")
			}
		}

		return ctx.Result, nil
	}

	// If an access denied endpoint was specified, redirect the user agent.
	// Otherwise, invoke the RemoteFailure event for further processing.
	if ctx.AccessDeniedPath != "" {
		uri := ctx.AccessDeniedPath
		if strings.TrimSpace(ctx.ReturnUrlParameter) != "" &&
			strings.TrimSpace(ctx.ReturnUrl) != "" {

			uri = utils.AddQuery(uri, ctx.ReturnUrlParameter, ctx.ReturnUrl)
		}
		http.Redirect(h.Response(), h.Request(), h.BuildRedirectUri(uri), http.StatusFound)

		return auth.Handle(), nil
	}

	return auth.HandleRequestNoResult(), nil
}
