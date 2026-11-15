// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package thirdpartylogin

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gonewx/godi"

	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// Parameter names of a login initiation request (OpenID Connect Core 1.0
// section 4).
const (
	ParameterIssuer        = "iss"
	ParameterLoginHint     = "login_hint"
	ParameterTargetLinkUri = "target_link_uri"
)

var (
	// ErrNotRegistered reports a client that registers no login initiation
	// endpoint.
	ErrNotRegistered = errors.New("thirdpartylogin: client registers no initiate_login_uri")
	// ErrInvalidInitiateLoginUri reports a registered login initiation
	// endpoint that is not an absolute https URI.
	ErrInvalidInitiateLoginUri = errors.New("thirdpartylogin: client initiate_login_uri is not an absolute https URI")
	// ErrInvalidIssuer reports a current issuer identifier that is not an
	// https URL with a host.
	ErrInvalidIssuer = errors.New("thirdpartylogin: issuer identifier is not an https URL")
	// ErrInvalidTargetLinkUri reports a target_link_uri that is not an
	// absolute http or https URL with a host.
	ErrInvalidTargetLinkUri = errors.New("thirdpartylogin: target_link_uri is not an absolute http or https URL")
	// ErrNoRequestScope reports a request that wicket's request scope does
	// not wrap.
	ErrNoRequestScope = errors.New("thirdpartylogin: request carries no wicket request scope")
)

// Parameters are the optional parameters of a login initiation request. An
// empty value is left out of the request.
type Parameters struct {
	// LoginHint hints the client about the login identifier the user may
	// use.
	LoginHint string
	// TargetLinkUri is where the client is asked to send the user after the
	// login; it must be an absolute http or https URL.
	TargetLinkUri string
}

// BuildInitiationUrl returns the login initiation URL of client: its
// registered InitiateLoginUri with iss set to issuer and login_hint and
// target_link_uri set to the non-empty parameters. Query parameters the
// registered URI carries are kept, except that the three parameters above are
// always replaced, and removed when the corresponding value is empty.
func BuildInitiationUrl(client *storage_models.Client, issuer string, params Parameters) (string, error) {
	if client == nil || client.InitiateLoginUri == "" {
		return "", ErrNotRegistered
	}
	if !storage_models.IsAbsoluteHttpsUri(client.InitiateLoginUri) {
		return "", ErrInvalidInitiateLoginUri
	}
	if !storage_models.IsAbsoluteHttpsUri(issuer) {
		return "", ErrInvalidIssuer
	}
	if params.TargetLinkUri != "" && !isAbsoluteUrl(params.TargetLinkUri) {
		return "", ErrInvalidTargetLinkUri
	}
	target, err := url.Parse(client.InitiateLoginUri)
	if err != nil {
		return "", ErrInvalidInitiateLoginUri
	}
	query, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return "", ErrInvalidInitiateLoginUri
	}
	query.Set(ParameterIssuer, issuer)
	setOrDelete(query, ParameterLoginHint, params.LoginHint)
	setOrDelete(query, ParameterTargetLinkUri, params.TargetLinkUri)
	target.RawQuery = query.Encode()
	target.ForceQuery = false
	return target.String(), nil
}

// Initiate sends the browser to the login initiation endpoint of the enabled
// client clientId. It must run inside a host request that wicket's request
// scope wraps. It loads the client through the client store of that scope,
// so a client that is absent, disabled or invalidly configured yields the
// store's error (extensions.IsClientRejected reports it), and takes iss from
// the issuer of the current request. On success it answers with 302 Found
// and Cache-Control: no-store; on any error it writes nothing to w.
func Initiate(w http.ResponseWriter, r *http.Request, clientId string, params Parameters) error {
	if r == nil {
		return ErrNoRequestScope
	}
	scope := hosting.ScopeFrom(r.Context())
	if scope == nil {
		return ErrNoRequestScope
	}
	store, ok := godi.Get[storage.ClientStore](scope)
	if !ok || store == nil {
		return ErrNoRequestScope
	}
	issuers, ok := godi.Get[services.IssuerNameService](scope)
	if !ok || issuers == nil {
		return ErrNoRequestScope
	}
	client, err := extensions.FindEnabledClientById(r.Context(), store, clientId)
	if err != nil {
		return fmt.Errorf("thirdpartylogin: load client %q: %w", clientId, err)
	}
	location, err := BuildInitiationUrl(client, issuers.GetCurrent(), params)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
	return nil
}

func isAbsoluteUrl(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https")
}

func setOrDelete(query url.Values, name, value string) {
	if value == "" {
		query.Del(name)
		return
	}
	query.Set(name, value)
}
