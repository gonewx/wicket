// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/clientcert"
	"github.com/gonewx/wicket/keymgmt"
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

	// Mutual TLS client authentication, see client_certificate.go.
	clientCertificateEnabled bool
	clientCertificateOptions clientcert.Options
	clientCertificateSource  clientcert.CertificateSource

	// Hardening options, see hardening.go.
	asymmetricRequestObjectsRequired        bool
	clientCredentialsAuthenticationRequired bool
}

func NewServerConfig() *ServerConfig {
	return &ServerConfig{}
}

// storeSeam describes one store injection seam for the assembly-time
// validation in Freeze. A seam is satisfied when the host injected a provider;
// otherwise the host must have declared the in-memory fallback explicitly.
//
// The authorization parameters message store seam is special: it is read
// directly by the ReturnUrlParser factory (no container wrapper, di/
// lifecycle.go covers the other ten seams), so its lifecycle belongs to the
// host — the host that injected the store owns closing it, and the container
// never releases it.
type storeSeam struct {
	name     string
	injected func() bool
}

// storeSeams enumerates every store seam the composition root validates.
func (c *ServerConfig) storeSeams() []storeSeam {
	return []storeSeam{
		{"authorization parameters message store", func() bool { return c.authorizationParametersMessageStoreProvider != nil }},
		{"persisted grant store", func() bool { return c.persistedGrantStoreProvider != nil }},
		{"device flow store", func() bool { return c.deviceFlowStoreProvider != nil }},
		{"backchannel authentication request store", func() bool { return c.backchannelAuthenticationRequestStoreProvider != nil }},
		{"authorization code store", func() bool { return c.authorizationCodeStoreProvider != nil }},
		{"refresh token store", func() bool { return c.refreshTokenStoreProvider != nil }},
		{"reference token store", func() bool { return c.referenceTokenStoreProvider != nil }},
		{"user consent store", func() bool { return c.userConsentStoreProvider != nil }},
		{"session store", func() bool { return c.sessionStoreProvider != nil }},
		{"distributed cache", func() bool { return c.distributedCacheProvider != nil }},
		{"key record store", func() bool { return c.recordStoreProvider != nil }},
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
	c.requireReplayRegistrySeam()
	if c.allowInMemoryFallback {
		return
	}
	for _, seam := range c.storeSeams() {
		if !seam.injected() {
			panic(fmt.Sprintf("store seam %q not injected by host and in-memory fallback not declared", seam.name))
		}
	}
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
