// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"log/slog"
	"net/url"
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/utils"
	validators_impl "github.com/gonewx/wicket/validators/impl"
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
	// clientAssertionSigningAlgorithms lists the signature algorithms of the
	// registered private_key_jwt parser, in configuration order.
	clientAssertionSigningAlgorithms []string
	// asymmetricRequestObjectsOnly is set when request objects are accepted
	// only with an asymmetric signature.
	asymmetricRequestObjectsOnly bool
}

// clientAssertionAlgorithmSource is the secret parser the client assertion
// signing algorithms come from.
type clientAssertionAlgorithmSource interface {
	AuthenticationMethod() string
	SigningAlgorithms() []string
}

var _ clientAssertionAlgorithmSource = (*clientassertion.Parser)(nil)

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

// unregisteredTlsMethod reports whether method is a tls client authentication
// method without a registered parser providing it.
func (a discoveryAssembly) unregisteredTlsMethod(method string) bool {
	return isTlsAuthenticationMethod(method) && !slices.Contains(a.authenticationMethods, method)
}

// advertisesClientAssertion reports whether a private_key_jwt parser is
// registered and the filtered document still lists that method.
func (a discoveryAssembly) advertisesClientAssertion(document map[string]any) bool {
	method := wicket.EndpointAuthenticationMethodsPrivateKeyJwt
	if !slices.Contains(a.authenticationMethods, method) {
		return false
	}
	switch values := document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported].(type) {
	case []string:
		return slices.Contains(values, method)
	case []any:
		return slices.Contains(values, any(method))
	default:
		return false
	}
}

func isTlsAuthenticationMethod(method string) bool {
	return method == wicket.EndpointAuthenticationMethodsTlsClientAuth ||
		method == wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
}

// filterDiscoveryAdvertisement removes the entries of a generated discovery
// document that the running assembly cannot serve. Entries produced by the
// host's custom entries under keys the generator does not write are left
// untouched.
func filterDiscoveryAdvertisement(
	document map[string]any,
	baseUrl string,
	options *config_options.WicketOptions,
	assembly discoveryAssembly,
	logger *slog.Logger,
) {
	baseUrl = utils.RemoveTrailingSlash(baseUrl)
	filter := &discoveryFilter{document: document, baseUrl: baseUrl, options: options}

	// endpoints: a URL under baseUrl must resolve to a registered route, and
	// a value that is not an absolute URL cannot be resolved by a client.
	for key, value := range document {
		if !isEndpointKey(key) {
			continue
		}
		raw, ok := value.(string)
		if !ok {
			continue
		}
		path, local := filter.localPath(raw)
		if local {
			if assembly.hasEndpointPath(path) {
				continue
			}
		} else if isAbsoluteUrl(raw) {
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

	// mutual TLS: each tls method needs its own registered parser; the
	// remaining mutual TLS entries need at least one of them.
	mtlsRemoved := filter.removeListValues(wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported, assembly.unregisteredTlsMethod)
	if assembly.hasTlsClientAuthentication() {
		mtlsRemoved = filter.pruneMtlsAliases(assembly) || mtlsRemoved
	} else {
		mtlsRemoved = filter.remove(wicket.DiscoveryTlsClientCertificateBoundAccessTokens) || mtlsRemoved
		mtlsRemoved = filter.remove(wicket.DiscoveryMtlsEndpointAliases) || mtlsRemoved
	}
	if mtlsRemoved && options.MutualTls.Enabled && logger != nil {
		logger.Warn("Mutual TLS is enabled but the current assembly cannot serve all of it; the unservable mutual TLS entries are not advertised in discovery.",
			slog.Bool("tls_client_authentication_registered", assembly.hasTlsClientAuthentication()))
	}

	// client assertion signing algorithms: the key is written only here and
	// only from the registered private_key_jwt parser, once the token
	// endpoint authentication methods are filtered.
	algorithmsKey := wicket.DiscoveryTokenEndpointAuthSigningAlgorithmsSupported
	hostValueRemoved := false
	if _, ok := document[algorithmsKey]; ok {
		filter.remove(algorithmsKey)
		hostValueRemoved = true
	}
	if assembly.advertisesClientAssertion(document) {
		if len(assembly.clientAssertionSigningAlgorithms) > 0 {
			document[algorithmsKey] = slices.Clone(assembly.clientAssertionSigningAlgorithms)
		} else if logger != nil {
			logger.Warn("private_key_jwt is advertised but its parser names no signing algorithm; token_endpoint_auth_signing_alg_values_supported is not advertised in discovery.")
		}
	}
	if hostValueRemoved && logger != nil {
		logger.Warn("A custom discovery entry named token_endpoint_auth_signing_alg_values_supported is ignored; the key is written only from the registered client assertion parser.")
	}

	// request object signing algorithms: only the accepted asymmetric ones
	// remain while request objects require an asymmetric signature.
	if assembly.asymmetricRequestObjectsOnly {
		filter.keepAsymmetricRequestObjectAlgorithms()
	}
}

// keepAsymmetricRequestObjectAlgorithms rebuilds the request object signing
// algorithm list with only the algorithms the asymmetric request object
// validator accepts, whether the value was generated or set by the host. A
// value that is not a list, or a list left empty, removes the key.
func (f *discoveryFilter) keepAsymmetricRequestObjectAlgorithms() {
	key := wicket.DiscoveryRequestObjectSigningAlgorithmsSupported
	value, ok := f.document[key]
	if !ok {
		return
	}
	accepted := validators_impl.AsymmetricRequestObjectSigningAlgorithms()
	var kept []string
	switch values := value.(type) {
	case []string:
		for _, algorithm := range values {
			if slices.Contains(accepted, algorithm) {
				kept = append(kept, algorithm)
			}
		}
	case []any:
		for _, entry := range values {
			if algorithm, ok := entry.(string); ok && slices.Contains(accepted, algorithm) {
				kept = append(kept, algorithm)
			}
		}
	}
	if len(kept) == 0 {
		delete(f.document, key)
		return
	}
	f.document[key] = kept
}

// generatedDiscoveryKeys holds the keys the discovery generator writes into
// the document. The generator writes most of them only under a switch, and a
// custom entry with the same name is discarded when the generator writes the
// key but lands in the document when it does not. The filter cannot tell
// these two cases apart after generation, so every value under one of these
// names is filtered like a generated one: the host cannot advertise anything
// under a generated name, whichever switch is off. A key the generator never
// writes (registration_endpoint, for example) can only come from the host.
// The set only tells where a value comes from; it does not decide whether
// anything can be served.
var generatedDiscoveryKeys = map[string]struct{}{
	wicket.DiscoveryAuthorizationEndpoint:                       {},
	wicket.DiscoveryAuthorizationResponseIssParameterSupported:  {},
	wicket.DiscoveryBackchannelAuthenticationEndpoint:           {},
	wicket.DiscoveryBackchannelLogoutSessionSupported:           {},
	wicket.DiscoveryBackchannelLogoutSupported:                  {},
	wicket.DiscoveryBackchannelTokenDeliveryModesSupported:      {},
	wicket.DiscoveryBackchannelUserCodeParameterSupported:       {},
	wicket.DiscoveryCheckSessionIframe:                          {},
	wicket.DiscoveryClaimsSupported:                             {},
	wicket.DiscoveryCodeChallengeMethodsSupported:               {},
	wicket.DiscoveryDeviceAuthorizationEndpoint:                 {},
	wicket.DiscoveryEndSessionEndpoint:                          {},
	wicket.DiscoveryFrontChannelLogoutSessionSupported:          {},
	wicket.DiscoveryFrontChannelLogoutSupported:                 {},
	wicket.DiscoveryGrantTypesSupported:                         {},
	wicket.DiscoveryIdTokenSigningAlgorithmsSupported:           {},
	wicket.DiscoveryIntrospectionEndpoint:                       {},
	wicket.DiscoveryIssuer:                                      {},
	wicket.DiscoveryJwksUri:                                     {},
	wicket.DiscoveryMtlsEndpointAliases:                         {},
	wicket.DiscoveryRequestObjectSigningAlgorithmsSupported:     {},
	wicket.DiscoveryRequestParameterSupported:                   {},
	wicket.DiscoveryRequestUriParameterSupported:                {},
	wicket.DiscoveryResponseModesSupported:                      {},
	wicket.DiscoveryResponseTypesSupported:                      {},
	wicket.DiscoveryRevocationEndpoint:                          {},
	wicket.DiscoveryScopesSupported:                             {},
	wicket.DiscoverySubjectTypesSupported:                       {},
	wicket.DiscoveryTlsClientCertificateBoundAccessTokens:       {},
	wicket.DiscoveryTokenEndpoint:                               {},
	wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported: {},
	wicket.DiscoveryUserInfoEndpoint:                            {},
}

// handlerWrittenDiscoveryKeys holds the keys the discovery handler itself
// writes after generation. A custom entry under one of these names is never
// a host entry: only the handler decides whether the key is advertised.
var handlerWrittenDiscoveryKeys = map[string]struct{}{
	wicket.DiscoveryTokenEndpointAuthSigningAlgorithmsSupported: {},
	wicket.DiscoveryPushedAuthorizationRequestEndpoint:          {},
	wicket.DiscoveryRequirePushedAuthorizationRequests:          {},
	wicket.DiscoveryDPoPSigningAlgValuesSupported:               {},
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

// localPath returns the route path of a URL located under baseUrl. The
// scheme and host compare without regard to case, as the route paths do.
func (f *discoveryFilter) localPath(raw string) (string, bool) {
	rest, ok := f.cutBaseUrl(raw)
	if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
		return "", false
	}
	return routePath(rest), true
}

func (f *discoveryFilter) cutBaseUrl(raw string) (string, bool) {
	if len(raw) < len(f.baseUrl) || !strings.EqualFold(raw[:len(f.baseUrl)], f.baseUrl) {
		return "", false
	}
	return raw[len(f.baseUrl):], true
}

func routePath(rest string) string {
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	return utils.EnsureLeadingSlash(rest)
}

func isAbsoluteUrl(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.IsAbs() && parsed.Host != ""
}

// isHostEntry reports whether the document value of key was produced by the
// host's custom entries rather than by the generator: the key is a custom
// entry and is not a key the generator writes. A custom entry named
// like a generated key never overrides the generated value, so it is filtered
// like any generated entry and cannot re-advertise a withdrawn capability.
func (f *discoveryFilter) isHostEntry(key string) bool {
	if _, ok := f.options.Discovery.CustomEntries[key]; !ok {
		return false
	}
	_, generated := generatedDiscoveryKeys[key]
	_, handlerWritten := handlerWrittenDiscoveryKeys[key]
	return !generated && !handlerWritten
}

func (f *discoveryFilter) remove(key string) bool {
	if _, ok := f.document[key]; !ok || f.isHostEntry(key) {
		return false
	}
	delete(f.document, key)
	return true
}

// removeListValues rebuilds the string list under key without the values
// matched by drop. A list decoded from configuration arrives as []any; its
// string elements are judged the same way. It reports whether anything was
// removed.
func (f *discoveryFilter) removeListValues(key string, drop func(string) bool) bool {
	if f.isHostEntry(key) {
		return false
	}
	switch values := f.document[key].(type) {
	case []string:
		if !slices.ContainsFunc(values, drop) {
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
	case []any:
		dropped := func(value any) bool {
			text, ok := value.(string)
			return ok && drop(text)
		}
		if !slices.ContainsFunc(values, dropped) {
			return false
		}
		kept := make([]any, 0, len(values))
		for _, value := range values {
			if !dropped(value) {
				kept = append(kept, value)
			}
		}
		f.document[key] = kept
		return true
	default:
		return false
	}
}

// pruneMtlsAliases keeps only the aliases whose primary endpoint is still
// advertised and, for an alias under baseUrl, whose path is a registered
// route. It drops the aliases entry once it is empty.
func (f *discoveryFilter) pruneMtlsAliases(assembly discoveryAssembly) bool {
	key := wicket.DiscoveryMtlsEndpointAliases
	if f.isHostEntry(key) {
		return false
	}
	switch aliases := f.document[key].(type) {
	case map[string]string:
		kept := make(map[string]string, len(aliases))
		for name, value := range aliases {
			if f.keepMtlsAlias(assembly, name, value) {
				kept[name] = value
			}
		}
		return f.replaceAliases(key, len(aliases), len(kept), kept)
	case map[string]any:
		kept := make(map[string]any, len(aliases))
		for name, value := range aliases {
			if f.keepMtlsAlias(assembly, name, value) {
				kept[name] = value
			}
		}
		return f.replaceAliases(key, len(aliases), len(kept), kept)
	default:
		return false
	}
}

func (f *discoveryFilter) keepMtlsAlias(assembly discoveryAssembly, name string, value any) bool {
	if _, ok := f.document[name]; !ok {
		return false
	}
	raw, ok := value.(string)
	if !ok {
		return false
	}
	path, local := f.aliasPath(raw)
	if local {
		return assembly.hasEndpointPath(path)
	}
	return isAbsoluteUrl(raw)
}

// aliasPath returns the route path of a path-form alias URL. With a mutual
// TLS domain name configured the aliases live on another host (domain or
// sub-domain form) and are not local. Otherwise the alias is built by
// appending the route to baseUrl, where the separating slash may be missing,
// so any URL starting with baseUrl is read as local.
func (f *discoveryFilter) aliasPath(raw string) (string, bool) {
	if f.options.MutualTls.DomainName != "" {
		return "", false
	}
	rest, ok := f.cutBaseUrl(raw)
	if !ok {
		return "", false
	}
	return routePath(rest), true
}

func (f *discoveryFilter) replaceAliases(key string, before int, after int, kept any) bool {
	if after == 0 {
		delete(f.document, key)
		return true
	}
	f.document[key] = kept
	return after < before
}
