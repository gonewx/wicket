// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"log/slog"
	"reflect"
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/utils"
)

// backChannelLogoutCapability is the capability marker a back-channel logout
// service implements to declare that it actually delivers logout
// notifications to relying parties. Only an implementation that returns true
// lets discovery advertise back-channel logout support; a service without the
// method, or one returning false, keeps the back-channel logout keys out of
// the discovery document.
type backChannelLogoutCapability interface {
	DeliversBackChannelLogout() bool
}

// discoveryAssembly carries the facts about the running assembly that decide
// which generated discovery entries can actually be served.
type discoveryAssembly struct {
	// endpointPaths holds the registered endpoint route paths (leading slash).
	endpointPaths []string
	// backChannelLogout is the resolved back-channel logout service.
	backChannelLogout any
	// authenticationMethods lists the methods of the registered secret parsers.
	authenticationMethods []string
}

func (a discoveryAssembly) hasEndpointPath(path string) bool {
	for _, registered := range a.endpointPaths {
		if strings.EqualFold(registered, path) {
			return true
		}
	}
	return false
}

func (a discoveryAssembly) deliversBackChannelLogout() bool {
	capability, ok := a.backChannelLogout.(backChannelLogoutCapability)
	return ok && capability.DeliversBackChannelLogout()
}

func (a discoveryAssembly) hasTlsClientAuthentication() bool {
	return slices.ContainsFunc(a.authenticationMethods, isTlsAuthenticationMethod)
}

func isTlsAuthenticationMethod(method string) bool {
	return method == wicket.EndpointAuthenticationMethodsTlsClientAuth ||
		method == wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
}

// filterDiscoveryAdvertisement removes the entries of a generated discovery
// document that the running assembly cannot serve. Entries produced by the
// host's custom entries are left untouched.
func filterDiscoveryAdvertisement(
	document map[string]any,
	baseUrl string,
	options *config_options.WicketOptions,
	assembly discoveryAssembly,
	logger *slog.Logger,
) {
	baseUrl = utils.RemoveTrailingSlash(baseUrl)
	filter := &discoveryFilter{document: document, baseUrl: baseUrl, options: options}

	// endpoints: a URL under baseUrl must resolve to a registered route.
	for key, value := range document {
		if !isEndpointKey(key) {
			continue
		}
		raw, ok := value.(string)
		if !ok {
			continue
		}
		path, local := filter.localPath(raw)
		if !local || assembly.hasEndpointPath(path) {
			continue
		}
		filter.remove(key)
	}

	// device_code is reachable only through the device authorization endpoint.
	if _, ok := document[wicket.DiscoveryDeviceAuthorizationEndpoint]; !ok {
		filter.removeListValues(wicket.DiscoveryGrantTypesSupported, func(value string) bool {
			return value == wicket.GrantTypeDeviceCode
		})
	}

	// back-channel logout needs a service that delivers notifications.
	if !assembly.deliversBackChannelLogout() {
		filter.remove(wicket.DiscoveryBackchannelLogoutSupported)
		filter.remove(wicket.DiscoveryBackchannelLogoutSessionSupported)
	}

	// iss response parameter follows the emitting switch.
	if !options.EmitIssuerIdentificationResponseParameter {
		filter.remove(wicket.DiscoveryAuthorizationResponseIssParameterSupported)
	}

	// mutual TLS needs a registered tls client authentication parser.
	mtlsRemoved := false
	if assembly.hasTlsClientAuthentication() {
		mtlsRemoved = filter.pruneMtlsAliases()
	} else {
		mtlsRemoved = filter.removeListValues(wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported, isTlsAuthenticationMethod)
		mtlsRemoved = filter.remove(wicket.DiscoveryTlsClientCertificateBoundAccessTokens) || mtlsRemoved
		mtlsRemoved = filter.remove(wicket.DiscoveryMtlsEndpointAliases) || mtlsRemoved
	}
	if mtlsRemoved && options.MutualTls.Enabled && logger != nil {
		logger.Warn("Mutual TLS is enabled but the current assembly cannot serve all of it; the unservable mutual TLS entries are not advertised in discovery.",
			slog.Bool("tls_client_authentication_registered", assembly.hasTlsClientAuthentication()))
	}
}

func isEndpointKey(key string) bool {
	return strings.HasSuffix(key, "_endpoint") ||
		key == wicket.DiscoveryCheckSessionIframe ||
		key == wicket.DiscoveryJwksUri
}

type discoveryFilter struct {
	document map[string]any
	baseUrl  string
	options  *config_options.WicketOptions
}

// localPath returns the route path of a URL located under baseUrl.
func (f *discoveryFilter) localPath(raw string) (string, bool) {
	rest, ok := strings.CutPrefix(raw, f.baseUrl)
	if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
		return "", false
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	return utils.EnsureLeadingSlash(rest), true
}

// isHostEntry reports whether the document value of key was produced by the
// host's custom entries rather than by the generator.
func (f *discoveryFilter) isHostEntry(key string) bool {
	custom, ok := f.options.Discovery.CustomEntries[key]
	if !ok {
		return false
	}
	value := f.document[key]
	if reflect.DeepEqual(value, custom) {
		return true
	}
	if text, ok := custom.(string); ok && f.options.Discovery.ExpandRelativePathsInCustomEntries {
		if rest, ok := strings.CutPrefix(text, "~/"); ok {
			return reflect.DeepEqual(value, f.baseUrl+"/"+strings.TrimLeft(rest, "/"))
		}
	}
	return false
}

func (f *discoveryFilter) remove(key string) bool {
	if _, ok := f.document[key]; !ok || f.isHostEntry(key) {
		return false
	}
	delete(f.document, key)
	return true
}

// removeListValues rebuilds the string list under key without the values
// matched by drop. It reports whether anything was removed.
func (f *discoveryFilter) removeListValues(key string, drop func(string) bool) bool {
	values, ok := f.document[key].([]string)
	if !ok || f.isHostEntry(key) || !slices.ContainsFunc(values, drop) {
		return false
	}
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if !drop(value) {
			kept = append(kept, value)
		}
	}
	f.document[key] = kept
	return true
}

// pruneMtlsAliases keeps only the aliases whose primary endpoint is still
// advertised and drops the aliases entry once it is empty.
func (f *discoveryFilter) pruneMtlsAliases() bool {
	key := wicket.DiscoveryMtlsEndpointAliases
	if f.isHostEntry(key) {
		return false
	}
	switch aliases := f.document[key].(type) {
	case map[string]string:
		kept := make(map[string]string, len(aliases))
		for name, value := range aliases {
			if _, ok := f.document[name]; ok {
				kept[name] = value
			}
		}
		return f.replaceAliases(key, len(aliases), len(kept), kept)
	case map[string]any:
		kept := make(map[string]any, len(aliases))
		for name, value := range aliases {
			if _, ok := f.document[name]; ok {
				kept[name] = value
			}
		}
		return f.replaceAliases(key, len(aliases), len(kept), kept)
	default:
		return false
	}
}

func (f *discoveryFilter) replaceAliases(key string, before int, after int, kept any) bool {
	if after == 0 {
		delete(f.document, key)
		return true
	}
	f.document[key] = kept
	return after < before
}
