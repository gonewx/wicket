// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"log/slog"
	"net/http"

	gois "github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/gonewx/wicket/services"
)

type Handler[T auth.SchemeOptions[T]] struct {
	auth.HandlerOverride

	OptionsMonitor optspkg.OptionsMonitor[T]
	Logger         *slog.Logger
	Options        T
	Events         any
	Scheme         *auth.Scheme
	Clock          services.SystemClock
	// CtxAccessor    accessor.HttpContextAccessor
	request  *http.Request
	response http.ResponseWriter

	result *auth.Result
}

func NewHandler[T auth.SchemeOptions[T]](
	// ctxAccessor accessor.HttpContextAccessor,
	optionsMonitor optspkg.OptionsMonitor[T],
	logger *slog.Logger,
	clock services.SystemClock,
	override auth.HandlerOverride,
) auth.Handler {
	h := &Handler[T]{
		// CtxAccessor:    ctxAccessor,
		OptionsMonitor: optionsMonitor,
		Logger:         logger,
		Clock:          clock,
	}

	// if override != nil {
	h.HandlerOverride = override
	// }

	return h
}

func (h *Handler[T]) Request() *http.Request {
	return h.request
}

func (h *Handler[T]) Response() http.ResponseWriter {
	return h.response
}

func (h *Handler[T]) Initialize(
	request *http.Request, response http.ResponseWriter,
	scheme *auth.Scheme,
) error {
	if scheme == nil {
		return gois.ArgumentNullException
	}

	if request == nil || response == nil {
		return gois.ArgumentNullException
	}

	h.Scheme = scheme
	h.request = request
	h.response = response
	var err error
	h.Options, err = h.OptionsMonitor.Get(scheme.Name)
	if err != nil {
		return err
	}

	if err := h.InitializeEvents(); err != nil {
		return err
	}
	if err := h.HandlerOverride.InitializeHandler(); err != nil {
		return err
	}
	return nil
}

func (h *Handler[T]) InitializeEvents() error {
	h.Events = h.Options.Events()

	if h.Events == nil {
		// if h.HandlerOverride == nil {
		// 	return fmt.Errorf("HandlerOverride is nil")
		// }
		h.Events = h.HandlerOverride.CreateEvents()
	}

	return nil
}

func (h *Handler[T]) CreateEvents() any {
	return nil
}

func (h *Handler[T]) InitializeHandler() error {
	return nil
}

func (h *Handler[T]) Authenticate() (*auth.Result, error) {
	target := h.ResolveTarget(h.Options.ForwardAuthenticate())
	if target != "" {
		svc, err := service(h.request.Context())
		if err != nil {
			return nil, err
		}
		return svc.Authenticate(h.Request(), h.Response(), target)
	}

	// Calling Authenticate more than once should always return the original value.

	result, err := h.handleAuthenticateOnce()
	if err != nil {
		return nil, err
	}

	if result == nil {
		result = auth.NoResult()
	}

	if result.Failure == nil {
		ticket := result.Ticket
		if ticket != nil && ticket.Principal != nil {
			if h.Logger.Enabled(h.request.Context(), slog.LevelDebug) {
				h.Logger.Debug("auth.Scheme was successfully authenticated.", slog.String("auth.Scheme", h.Scheme.Name))
			} else {
				h.Logger.Debug("auth.Scheme was not authenticated.", slog.String("auth.Scheme", h.Scheme.Name))
			}
		}
	} else {
		h.Logger.Debug("auth.Scheme was not authenticated. Failure message:", slog.String("auth.Scheme", h.Scheme.Name), slog.String("Failure message", result.Failure.Error()))

	}
	return result, nil
}

func (h *Handler[T]) Challenge(properties *auth.Properties) error {
	target := h.ResolveTarget(h.Options.ForwardChallenge())
	if target != "" {
		svc, err := service(h.request.Context())
		if err != nil {
			return err
		}
		return svc.Challenge(h.Request(), h.Response(), target, properties)
	}

	if properties == nil {
		properties = auth.NewProperties()
	}

	_ = h.HandlerOverride.HandleChallenge(properties)

	h.Logger.Debug("auth.Scheme was challenged.", slog.String("auth.Scheme", h.Scheme.Name))

	return nil
}

func (h *Handler[T]) Forbid(properties *auth.Properties) error {
	target := h.ResolveTarget(h.Options.ForwardForbid())
	if target != "" {
		svc, err := service(h.request.Context())
		if err != nil {
			return err
		}
		return svc.Forbid(h.Request(), h.Response(), target, properties)
	}

	if properties == nil {
		properties = auth.NewProperties()
	}

	_ = h.HandlerOverride.HandleForbidden(properties)

	h.Logger.Debug("auth.Scheme was forbidden.", slog.String("auth.Scheme", h.Scheme.Name))

	return nil
}

func (h *Handler[T]) BuildRedirectUri(targetPath string) string {
	scheme := "http"
	if h.Request().TLS != nil {
		scheme = "https"
	}

	return scheme + "://" + h.Request().Host + h.OriginalPathBase() + targetPath
}

// ResolveTarget Resolves the scheme that this authentication operation is forwarded to.
func (h *Handler[T]) ResolveTarget(scheme string) string {
	var target string
	if scheme != "" {
		target = scheme
	} else {
		if h.Options.ForwardDefaultSelector() != nil {
			target = h.Options.ForwardDefaultSelector()(h.Request())
		} else {
			target = h.Options.ForwardDefault()
		}
	}

	// Prevent self targetting
	if target == h.Scheme.Name {
		return ""
	}
	return target
}

func (h *Handler[T]) handleAuthenticateOnce() (*auth.Result, error) {
	var err error
	if h.result == nil {
		h.result, err = h.HandlerOverride.HandleAuthenticate()
		if err != nil {
			return nil, err
		}
	}

	return h.result, nil
}

// OriginalPath Gets the path as seen by the authentication middleware.
func (h *Handler[T]) OriginalPath() string {
	ctx := h.Request().Context()
	if ctx == nil {
		return h.Request().URL.Path
	}

	feature := FeatureFrom(ctx)
	if feature == nil {
		return h.Request().URL.Path
	}
	return feature.OriginalPath()
}

// OriginalPathBase Gets the path base as seen by the authentication middleware.
func (h *Handler[T]) OriginalPathBase() string {
	pathBase := ""
	ctx := h.Request().Context()
	if ctx == nil {
		return pathBase
	}

	feature := FeatureFrom(ctx)
	if feature == nil {
		return pathBase
	}
	return feature.OriginalPathBase()
}

func (h *Handler[T]) HandleChallenge(properties *auth.Properties) error {
	h.Response().WriteHeader(http.StatusUnauthorized)
	return nil
}

func (h *Handler[T]) HandleForbidden(properties *auth.Properties) error {
	h.Response().WriteHeader(http.StatusForbidden)
	return nil
}

// func (h *Handler[T]) FinishResponse() error {
// 	return h.HandlerOverride.HandleFinishResponse()
// }

func (h *Handler[T]) HandleAuthenticate() (*auth.Result, error) {
	return nil, nil
}

// func (h *Handler[T]) HandleFinishResponse() error {
// 	return nil
// }
