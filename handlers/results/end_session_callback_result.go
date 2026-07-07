// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package results

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gonewx/godi"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type EndSessionCallbackResult struct {
	Result *validators_models.EndSessionCallbackValidationResult

	logger  *slog.Logger
	options *config_options.IdentityServerOptions
}

func NewEndSessionCallbackResult(
	result *validators_models.EndSessionCallbackValidationResult,
) *EndSessionCallbackResult {
	h := &EndSessionCallbackResult{
		Result: result,
	}
	return h
}

func newEndSessionCallbackResult(
	result *validators_models.EndSessionCallbackValidationResult,
	options *config_options.IdentityServerOptions,
) *EndSessionCallbackResult {
	h := &EndSessionCallbackResult{
		Result:  result,
		options: options,
	}
	return h
}

func (escr *EndSessionCallbackResult) init(ctx context.Context) {
	if escr.options == nil {
		// AD-10: EndSessionCallbackResult resolves options from RequestServices.
		escr.options = godi.GetRequired[*config_options.IdentityServerOptions](hosting.ScopeFrom(ctx))
	}
}

func (escr *EndSessionCallbackResult) addCspHeaders(w http.ResponseWriter) {
	if !escr.options.Authentication.RequireCspFrameSrcForSignout {
		return
	}

	var sb bytes.Buffer
	origins := utils.Select(escr.Result.FrontChannelLogoutUrls, func(x string) string {
		u, err := url.Parse(x)
		if err != nil {
			return ""
		}
		return u.Scheme + "://" + u.Host
	})

	if origins != nil {
		for _, origin := range utils.Distinct(origins) {
			if origin != "" {
				sb.WriteString(origin)
				if sb.Len() > 0 {
					sb.WriteString(" ")
				}
			}
		}
	}

	// the hash matches the embedded style element being used below
	AddStyleCspHeaders(w, escr.options.Csp, "sha256-e6FQZewefmod2S/5T11pTXjzE2vn3/8GRwWOs917YE4=", sb.String())
}

func (escr *EndSessionCallbackResult) getHtml() string {
	var sb bytes.Buffer
	sb.WriteString("<!DOCTYPE html><html><style>iframe{{display:none;width:0;height:0;}}</style><body>")

	if escr.Result.FrontChannelLogoutUrls != nil {
		for _, u := range escr.Result.FrontChannelLogoutUrls {
			sb.WriteString(fmt.Sprintf("<iframe loading='eager' allow='' src='%s'></iframe>\n", html.EscapeString(u)))
		}
	}

	return sb.String()
}

func (escr *EndSessionCallbackResult) Execute(w http.ResponseWriter, r *http.Request) error {
	escr.init(r.Context())

	if escr.Result.Error != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}

	HttpRespSetNoCache(w)
	escr.addCspHeaders(w)

	if err := HttpRespWriteHtml(w, []byte(escr.getHtml()), ""); err != nil {
		escr.logger.Error("Failed to write response", slog.String("err", err.Error()))
		return err
	}
	return nil
}
