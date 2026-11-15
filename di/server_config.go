// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/clientcert"
	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

// ServerConfig stores host-provided runtime seams.
// input: setter values or providers -> behavior: read current configured seam -> output: seam value.
type ServerConfig struct {
	frozen                bool
	allowInMemoryFallback bool

	logger *slog.Logger

	signingCredentialStoresProvider func() []storage.SigningCredentialStore
	validationKeysStoresProvider    func() []storage.ValidationKeysStore
	clientsProvider                 func() []*storage_models.Client
	identityScopesProvider          func() []*storage_models.IdentityResource
	apiResourcesProvider            func() []*storage_models.ApiResource
	apiScopesProvider               func() []*storage_models.ApiScope

	// clientStore is the host-injected client store, see SetClientStore. It
	// excludes clientsProvider.
	clientStore storage.ClientStore

	// Client registration store seam, see client_registration_store.go. It
	// also serves the client store seam and excludes clientStore and
	// clientsProvider. The seam is required exactly when
	// clientRegistrationDependentFeatures is non-empty.
	clientRegistrationStore             storage.ClientRegistrationStore
	clientRegistrationDependentFeatures []string

	authorizationParametersMessageStoreProvider   func() storage.AuthorizationParametersMessageStore
	persistedGrantStoreProvider                   func() storage.PersistedGrantStore
	deviceFlowStoreProvider                       func() storage.DeviceFlowStore
	backchannelAuthenticationRequestStoreProvider func() storage.BackchannelAuthenticationRequestStore

	authorizationCodeStoreProvider func() storage.AuthorizationCodeStore
	refreshTokenStoreProvider      func() storage.RefreshTokenStore
	referenceTokenStoreProvider    func() storage.ReferenceTokenStore
	userConsentStoreProvider       func() storage.UserConsentStore
	sessionStoreProvider           func() sessionpkg.Store
	distributedCacheProvider       func() services.DistributedCache
	recordStoreProvider            func() keymgmt.RecordStore

	authenticationHandlerProviders map[string]func(godi.Provider) auth.Handler

	backchannelAuthenticationUserValidator          validators.BackchannelAuthenticationUserValidator
	resourceOwnerValidator                          validators.ResourceOwnerPasswordValidator
	profileProvider                                 func() services.ProfileService
	backChannelLogoutHttpClient                     *http.Client
	backchannelAuthenticationNotificationHttpClient *http.Client

	externalFailurePath string

	// Replay registry seam, see replay_registry.go. The seam is required
	// exactly when replayDependentFeatures is non-empty.
	replayRegistryProvider              func() replay.Registry
	allowInMemoryReplayRegistryFallback bool
	replayDependentFeatures             []string

	privateKeyJwtOptions clientassertion.Options

	// DPoP options, see dpop.go. The enablement is recorded in
	// replayDependentFeatures.
	dpopOptions dpop.Options
	// dpopNonceKeys is the DPoP nonce key seam, see dpop_nonce.go. It is
	// required exactly when DPoP is enabled with RequireNonce.
	dpopNonceKeys dpop.NonceKeySource

	// Mutual TLS client authentication, see client_certificate.go.
	clientCertificateEnabled bool
	clientCertificateOptions clientcert.Options
	clientCertificateSource  clientcert.CertificateSource

	// Hardening options, see hardening.go.
	asymmetricRequestObjectsRequired        bool
	clientCredentialsAuthenticationRequired bool

	// requestedAcrRequired enforces the requested acr_values, see
	// requested_acr.go.
	requestedAcrRequired bool

	// accountCreationUrl is the host's account creation page, see
	// account_creation.go. Empty means account creation is not offered.
	accountCreationUrl string

	// Pushed authorization seams, see pushed_authorization.go. Both are
	// required exactly when pushedAuthorizationEnabled is set.
	pushedAuthorizationEnabled                bool
	pushedAuthorizationRequestStoreProvider   func() storage.PushedAuthorizationRequestStore
	pushedAuthorizationRequestStoreOnce       sync.Once
	pushedAuthorizationRequestStore           storage.PushedAuthorizationRequestStore
	pushedAuthorizationDataProtectionProvider dp.DataProtectionProvider
	pushedAuthorizationOptions                pushedauth.Options
	pushedAuthorizationProtectorOnce          sync.Once
	pushedAuthorizationProtector              dp.DataProtector
	pushedAuthorizationProtectorErr           error
}

func NewServerConfig() *ServerConfig {
	return &ServerConfig{}
}

// storeSeamCategory says what Freeze demands of a store seam the host did not
// inject.
type storeSeamCategory int

const (
	// storeSeamRequired must be injected unless the host declared the
	// in-memory fallback with AllowInMemoryFallback.
	storeSeamRequired storeSeamCategory = iota
	// storeSeamOptional may stay uninjected; the assembly then runs without a
	// store or on a fixed in-memory implementation, and Freeze logs a warning.
	storeSeamOptional
	// storeSeamFeatureRequired must be injected while its condition holds,
	// unless the host declared that seam's own fallback. AllowInMemoryFallback
	// does not exempt it.
	storeSeamFeatureRequired
)

func (c storeSeamCategory) String() string {
	switch c {
	case storeSeamRequired:
		return "required"
	case storeSeamOptional:
		return "optional"
	case storeSeamFeatureRequired:
		return "feature-required"
	default:
		return fmt.Sprintf("storeSeamCategory(%d)", int(c))
	}
}

// storeSeam describes one store injection seam for the assembly-time
// validation in Freeze.
//
// The authorization parameters message store seam is special: it is read
// directly by the ReturnUrlParser factory (no container wrapper, di/
// lifecycle.go covers the ten required seams), so its lifecycle belongs to the
// host — the host that injected the store owns closing it, and the container
// never releases it. The same holds for an injected client store, for an
// injected client registration store and for an injected pushed
// authorization request store.
type storeSeam struct {
	name     string
	category storeSeamCategory
	injected func() bool
	// condition and fallbackDeclared apply to storeSeamFeatureRequired only:
	// the seam is demanded while condition reports true, and fallbackDeclared
	// reports the host's per-seam fallback declaration.
	condition        func() bool
	fallbackDeclared func() bool
}

// storeSeams enumerates every store seam the composition root validates.
func (c *ServerConfig) storeSeams() []storeSeam {
	return []storeSeam{
		{name: "authorization parameters message store", category: storeSeamOptional, injected: func() bool { return c.authorizationParametersMessageStoreProvider != nil }},
		{name: "persisted grant store", injected: func() bool { return c.persistedGrantStoreProvider != nil }},
		{name: "device flow store", injected: func() bool { return c.deviceFlowStoreProvider != nil }},
		{name: "backchannel authentication request store", injected: func() bool { return c.backchannelAuthenticationRequestStoreProvider != nil }},
		{name: "authorization code store", injected: func() bool { return c.authorizationCodeStoreProvider != nil }},
		{name: "refresh token store", injected: func() bool { return c.refreshTokenStoreProvider != nil }},
		{name: "reference token store", injected: func() bool { return c.referenceTokenStoreProvider != nil }},
		{name: "user consent store", injected: func() bool { return c.userConsentStoreProvider != nil }},
		{name: "session store", injected: func() bool { return c.sessionStoreProvider != nil }},
		{name: "distributed cache", injected: func() bool { return c.distributedCacheProvider != nil }},
		{name: "key record store", injected: func() bool { return c.recordStoreProvider != nil }},
		{name: "client store", category: storeSeamOptional, injected: func() bool { return c.ClientStore() != nil }},
		{
			name:      clientRegistrationStoreSeamName,
			category:  storeSeamFeatureRequired,
			injected:  func() bool { return c.clientRegistrationStore != nil },
			condition: c.clientRegistrationStoreRequired,
		},
		{
			name:      pushedAuthorizationRequestStoreSeamName,
			category:  storeSeamFeatureRequired,
			injected:  func() bool { return c.pushedAuthorizationRequestStoreProvider != nil },
			condition: c.pushedAuthorizationRequired,
		},
		{
			name:      pushedAuthorizationDataProtectionSeamName,
			category:  storeSeamFeatureRequired,
			injected:  func() bool { return c.pushedAuthorizationDataProtectionProvider != nil },
			condition: c.pushedAuthorizationRequired,
		},
		{
			name:      dpopNonceKeySeamName,
			category:  storeSeamFeatureRequired,
			injected:  func() bool { return c.dpopNonceKeys != nil },
			condition: c.dpopNonceRequired,
		},
	}
}

// validateStoreSeams applies each seam's category to the host's injections.
// It panics on the first unmet seam and logs one warning per uninjected
// optional seam when logger is non-nil.
func validateStoreSeams(seams []storeSeam, allowInMemoryFallback bool, logger *slog.Logger) {
	for _, seam := range seams {
		if seam.injected() {
			continue
		}
		switch seam.category {
		case storeSeamOptional:
			if logger != nil {
				logger.Warn("optional store seam not injected by host", slog.String("seam", seam.name))
			}
		case storeSeamFeatureRequired:
			if seam.condition == nil {
				panic(fmt.Sprintf("store seam %q is feature-required but declares no condition", seam.name))
			}
			if !seam.condition() {
				continue
			}
			if seam.fallbackDeclared != nil && seam.fallbackDeclared() {
				continue
			}
			panic(fmt.Sprintf("store seam %q is required by an enabled feature, not injected by host and its fallback not declared", seam.name))
		default:
			if allowInMemoryFallback {
				continue
			}
			panic(fmt.Sprintf("store seam %q not injected by host and in-memory fallback not declared", seam.name))
		}
	}
}

// requireClientStoreSeam checks an injected client store: it excludes the
// static client list, and it must answer CORS origin lookups from the same
// data it serves clients from. An injected client registration store is held
// to the same rules and also excludes SetClientStore.
func (c *ServerConfig) requireClientStoreSeam() {
	c.requireClientRegistrationStoreSeam()
	if c.clientStore == nil {
		return
	}
	if c.clientsProvider != nil {
		panic("client store injected by host together with SetClients or SetClientsProvider; use one of them")
	}
	if _, ok := c.clientStore.(storage.ClientOriginLookup); !ok {
		panic(fmt.Sprintf("client store injected by host (%T) does not implement storage.ClientOriginLookup, which CORS decisions require", c.clientStore))
	}
}

// AllowInMemoryFallback declares that the host accepts the in-memory fallback
// implementations for store seams it did not inject. Development hosts call it
// before Freeze; production assembly must inject every store instead.
func (c *ServerConfig) AllowInMemoryFallback() {
	c.allowInMemoryFallback = true
}

func (c *ServerConfig) Freeze() {
	c.frozen = true
	c.requirePrivateKeyJwtOptions()
	c.requireDPoPOptions()
	c.requireDPoPNonceKeySeam()
	c.requireReplayRegistrySeam()
	c.requireClientStoreSeam()
	c.requirePushedAuthorizationDataProtectionSeam()
	validateStoreSeams(c.storeSeams(), c.allowInMemoryFallback, c.logger)
}

func (c *ServerConfig) Frozen() bool {
	return c != nil && c.frozen
}

func (c *ServerConfig) SetLogger(logger *slog.Logger) {
	c.logger = logger
}

func (c *ServerConfig) Logger() *slog.Logger {
	if c == nil {
		return nil
	}
	return c.logger
}

func (c *ServerConfig) SetSigningCredentialStoresProvider(provider func() []storage.SigningCredentialStore) {
	c.signingCredentialStoresProvider = provider
}

func (c *ServerConfig) SetSigningCredentialStores(stores []storage.SigningCredentialStore) {
	c.SetSigningCredentialStoresProvider(func() []storage.SigningCredentialStore { return stores })
}

func (c *ServerConfig) SigningCredentialStores() []storage.SigningCredentialStore {
	if c == nil || c.signingCredentialStoresProvider == nil {
		return nil
	}
	return c.signingCredentialStoresProvider()
}

func (c *ServerConfig) SetValidationKeysStoresProvider(provider func() []storage.ValidationKeysStore) {
	c.validationKeysStoresProvider = provider
}

func (c *ServerConfig) SetValidationKeysStores(stores []storage.ValidationKeysStore) {
	c.SetValidationKeysStoresProvider(func() []storage.ValidationKeysStore { return stores })
}

func (c *ServerConfig) ValidationKeysStores() []storage.ValidationKeysStore {
	if c == nil || c.validationKeysStoresProvider == nil {
		return nil
	}
	return c.validationKeysStoresProvider()
}

func (c *ServerConfig) SetClientsProvider(provider func() []*storage_models.Client) {
	c.clientsProvider = provider
}

func (c *ServerConfig) SetClients(clients []*storage_models.Client) {
	c.SetClientsProvider(func() []*storage_models.Client { return clients })
}

func (c *ServerConfig) Clients() []*storage_models.Client {
	if c == nil || c.clientsProvider == nil {
		return nil
	}
	return c.clientsProvider()
}

// SetClientStore injects the host's client store. The container always wraps
// it in the configuration-validating decorator, so every read path sees only
// clients whose configuration passes validation. The value must also
// implement storage.ClientOriginLookup, which CORS decisions read, and it
// excludes SetClients, SetClientsProvider and SetClientRegistrationStore;
// Freeze enforces both.
func (c *ServerConfig) SetClientStore(store storage.ClientStore) {
	c.clientStore = store
}

// ClientStore returns the host-injected client store: the value of
// SetClientStore, or the value of SetClientRegistrationStore when only that
// one was injected. It returns nil when the host feeds clients through
// SetClients or SetClientsProvider.
func (c *ServerConfig) ClientStore() storage.ClientStore {
	if c == nil {
		return nil
	}
	if c.clientStore != nil {
		return c.clientStore
	}
	if c.clientRegistrationStore != nil {
		return c.clientRegistrationStore
	}
	return nil
}

func (c *ServerConfig) SetIdentityScopesProvider(provider func() []*storage_models.IdentityResource) {
	c.identityScopesProvider = provider
}

func (c *ServerConfig) SetIdentityScopes(scopes []*storage_models.IdentityResource) {
	c.SetIdentityScopesProvider(func() []*storage_models.IdentityResource { return scopes })
}

func (c *ServerConfig) IdentityScopes() []*storage_models.IdentityResource {
	if c == nil || c.identityScopesProvider == nil {
		return nil
	}
	return c.identityScopesProvider()
}

func (c *ServerConfig) SetApiResourcesProvider(provider func() []*storage_models.ApiResource) {
	c.apiResourcesProvider = provider
}

func (c *ServerConfig) SetApiResources(resources []*storage_models.ApiResource) {
	c.SetApiResourcesProvider(func() []*storage_models.ApiResource { return resources })
}

func (c *ServerConfig) ApiResources() []*storage_models.ApiResource {
	if c == nil || c.apiResourcesProvider == nil {
		return nil
	}
	return c.apiResourcesProvider()
}

func (c *ServerConfig) SetApiScopesProvider(provider func() []*storage_models.ApiScope) {
	c.apiScopesProvider = provider
}

func (c *ServerConfig) SetApiScopes(scopes []*storage_models.ApiScope) {
	c.SetApiScopesProvider(func() []*storage_models.ApiScope { return scopes })
}

func (c *ServerConfig) ApiScopes() []*storage_models.ApiScope {
	if c == nil || c.apiScopesProvider == nil {
		return nil
	}
	return c.apiScopesProvider()
}

func (c *ServerConfig) SetAuthorizationParametersMessageStoreProvider(provider func() storage.AuthorizationParametersMessageStore) {
	c.authorizationParametersMessageStoreProvider = provider
}

func (c *ServerConfig) SetAuthorizationParametersMessageStore(store storage.AuthorizationParametersMessageStore) {
	c.SetAuthorizationParametersMessageStoreProvider(func() storage.AuthorizationParametersMessageStore { return store })
}

func (c *ServerConfig) AuthorizationParametersMessageStore() storage.AuthorizationParametersMessageStore {
	if c == nil || c.authorizationParametersMessageStoreProvider == nil {
		return nil
	}
	return c.authorizationParametersMessageStoreProvider()
}

func (c *ServerConfig) SetPersistedGrantStoreProvider(provider func() storage.PersistedGrantStore) {
	c.persistedGrantStoreProvider = provider
}

func (c *ServerConfig) SetPersistedGrantStore(store storage.PersistedGrantStore) {
	c.SetPersistedGrantStoreProvider(func() storage.PersistedGrantStore { return store })
}

func (c *ServerConfig) PersistedGrantStore() storage.PersistedGrantStore {
	if c == nil || c.persistedGrantStoreProvider == nil {
		return nil
	}
	return c.persistedGrantStoreProvider()
}

func (c *ServerConfig) SetDeviceFlowStoreProvider(provider func() storage.DeviceFlowStore) {
	c.deviceFlowStoreProvider = provider
}

func (c *ServerConfig) SetDeviceFlowStore(store storage.DeviceFlowStore) {
	c.SetDeviceFlowStoreProvider(func() storage.DeviceFlowStore { return store })
}

func (c *ServerConfig) DeviceFlowStore() storage.DeviceFlowStore {
	if c == nil || c.deviceFlowStoreProvider == nil {
		return nil
	}
	return c.deviceFlowStoreProvider()
}

func (c *ServerConfig) SetBackchannelAuthenticationRequestStoreProvider(provider func() storage.BackchannelAuthenticationRequestStore) {
	c.backchannelAuthenticationRequestStoreProvider = provider
}

func (c *ServerConfig) SetBackchannelAuthenticationRequestStore(store storage.BackchannelAuthenticationRequestStore) {
	c.SetBackchannelAuthenticationRequestStoreProvider(func() storage.BackchannelAuthenticationRequestStore { return store })
}

func (c *ServerConfig) BackchannelAuthenticationRequestStore() storage.BackchannelAuthenticationRequestStore {
	if c == nil || c.backchannelAuthenticationRequestStoreProvider == nil {
		return nil
	}
	return c.backchannelAuthenticationRequestStoreProvider()
}

func (c *ServerConfig) SetAuthorizationCodeStoreProvider(provider func() storage.AuthorizationCodeStore) {
	c.authorizationCodeStoreProvider = provider
}

func (c *ServerConfig) SetAuthorizationCodeStore(store storage.AuthorizationCodeStore) {
	c.SetAuthorizationCodeStoreProvider(func() storage.AuthorizationCodeStore { return store })
}

func (c *ServerConfig) AuthorizationCodeStore() storage.AuthorizationCodeStore {
	if c == nil || c.authorizationCodeStoreProvider == nil {
		return nil
	}
	return c.authorizationCodeStoreProvider()
}

func (c *ServerConfig) SetRefreshTokenStoreProvider(provider func() storage.RefreshTokenStore) {
	c.refreshTokenStoreProvider = provider
}

func (c *ServerConfig) SetRefreshTokenStore(store storage.RefreshTokenStore) {
	c.SetRefreshTokenStoreProvider(func() storage.RefreshTokenStore { return store })
}

func (c *ServerConfig) RefreshTokenStore() storage.RefreshTokenStore {
	if c == nil || c.refreshTokenStoreProvider == nil {
		return nil
	}
	return c.refreshTokenStoreProvider()
}

func (c *ServerConfig) SetReferenceTokenStoreProvider(provider func() storage.ReferenceTokenStore) {
	c.referenceTokenStoreProvider = provider
}

func (c *ServerConfig) SetReferenceTokenStore(store storage.ReferenceTokenStore) {
	c.SetReferenceTokenStoreProvider(func() storage.ReferenceTokenStore { return store })
}

func (c *ServerConfig) ReferenceTokenStore() storage.ReferenceTokenStore {
	if c == nil || c.referenceTokenStoreProvider == nil {
		return nil
	}
	return c.referenceTokenStoreProvider()
}

func (c *ServerConfig) SetUserConsentStoreProvider(provider func() storage.UserConsentStore) {
	c.userConsentStoreProvider = provider
}

func (c *ServerConfig) SetUserConsentStore(store storage.UserConsentStore) {
	c.SetUserConsentStoreProvider(func() storage.UserConsentStore { return store })
}

func (c *ServerConfig) UserConsentStore() storage.UserConsentStore {
	if c == nil || c.userConsentStoreProvider == nil {
		return nil
	}
	return c.userConsentStoreProvider()
}

func (c *ServerConfig) SetSessionStoreProvider(provider func() sessionpkg.Store) {
	c.sessionStoreProvider = provider
}

func (c *ServerConfig) SetSessionStore(store sessionpkg.Store) {
	c.SetSessionStoreProvider(func() sessionpkg.Store { return store })
}

func (c *ServerConfig) SessionStore() sessionpkg.Store {
	if c == nil || c.sessionStoreProvider == nil {
		return nil
	}
	return c.sessionStoreProvider()
}

func (c *ServerConfig) SetDistributedCacheProvider(provider func() services.DistributedCache) {
	c.distributedCacheProvider = provider
}

func (c *ServerConfig) SetDistributedCache(cache services.DistributedCache) {
	c.SetDistributedCacheProvider(func() services.DistributedCache { return cache })
}

func (c *ServerConfig) DistributedCache() services.DistributedCache {
	if c == nil || c.distributedCacheProvider == nil {
		return nil
	}
	return c.distributedCacheProvider()
}

func (c *ServerConfig) SetRecordStoreProvider(provider func() keymgmt.RecordStore) {
	c.recordStoreProvider = provider
}

func (c *ServerConfig) SetRecordStore(store keymgmt.RecordStore) {
	c.SetRecordStoreProvider(func() keymgmt.RecordStore { return store })
}

func (c *ServerConfig) RecordStore() keymgmt.RecordStore {
	if c == nil || c.recordStoreProvider == nil {
		return nil
	}
	return c.recordStoreProvider()
}

func (c *ServerConfig) SetBackchannelAuthenticationUserValidator(validator validators.BackchannelAuthenticationUserValidator) {
	c.backchannelAuthenticationUserValidator = validator
}

func (c *ServerConfig) BackchannelAuthenticationUserValidator() validators.BackchannelAuthenticationUserValidator {
	if c == nil {
		return nil
	}
	return c.backchannelAuthenticationUserValidator
}

func (c *ServerConfig) SetResourceOwnerValidator(validator validators.ResourceOwnerPasswordValidator) {
	c.resourceOwnerValidator = validator
}

func (c *ServerConfig) ResourceOwnerValidator() validators.ResourceOwnerPasswordValidator {
	if c == nil {
		return nil
	}
	return c.resourceOwnerValidator
}

// SetAuthenticationHandlerProvider installs a host-provided factory for the
// authentication handler keyed by the given scheme name. The composition root
// consults this seam before falling back to the built-in placeholder, so a
// host can supply the concrete handler for a scheme whose default registration
// is not yet available.
func (c *ServerConfig) SetAuthenticationHandlerProvider(scheme string, provider func(godi.Provider) auth.Handler) {
	if c.authenticationHandlerProviders == nil {
		c.authenticationHandlerProviders = map[string]func(godi.Provider) auth.Handler{}
	}
	c.authenticationHandlerProviders[scheme] = provider
}

func (c *ServerConfig) AuthenticationHandlerProvider(scheme string) func(godi.Provider) auth.Handler {
	if c == nil {
		return nil
	}
	return c.authenticationHandlerProviders[scheme]
}

func (c *ServerConfig) SetProfileProvider(provider func() services.ProfileService) {
	c.profileProvider = provider
}

func (c *ServerConfig) ProfileProvider() func() services.ProfileService {
	if c == nil {
		return nil
	}
	return c.profileProvider
}

func (c *ServerConfig) SetBackChannelLogoutHttpClient(client *http.Client) {
	c.backChannelLogoutHttpClient = client
}

// BackChannelLogoutHttpClient returns the host-provided client used to post
// back-channel logout tokens, or, when the host provided none, a default client
// with a bounded timeout that does not follow redirects, so a logout token is
// never forwarded to a location other than the pre-registered logout URI.
func (c *ServerConfig) BackChannelLogoutHttpClient() *http.Client {
	if c == nil {
		return nil
	}
	if c.backChannelLogoutHttpClient != nil {
		return c.backChannelLogoutHttpClient
	}
	return newDefaultBackChannelLogoutHttpClient()
}

func newDefaultBackChannelLogoutHttpClient() *http.Client {
	return &http.Client{
		Timeout: services_impl.BackChannelLogoutTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *ServerConfig) SetBackchannelAuthenticationNotificationHttpClient(client *http.Client) {
	c.backchannelAuthenticationNotificationHttpClient = client
}

func (c *ServerConfig) BackchannelAuthenticationNotificationHttpClient() *http.Client {
	if c == nil {
		return nil
	}
	return c.backchannelAuthenticationNotificationHttpClient
}

func (c *ServerConfig) SetExternalFailurePath(path string) {
	c.externalFailurePath = path
}

func (c *ServerConfig) ExternalFailurePath() string {
	if c == nil {
		return ""
	}
	return c.externalFailurePath
}
