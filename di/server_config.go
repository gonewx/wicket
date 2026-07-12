// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
)

// ServerConfig stores host-provided runtime seams.
// input: setter values or providers -> behavior: read current configured seam -> output: seam value.
type ServerConfig struct {
	frozen bool

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

	authenticationHandlerProviders map[string]func(godi.Provider) auth.Handler

	backchannelAuthenticationUserValidator          validators.BackchannelAuthenticationUserValidator
	resourceOwnerValidator                          validators.ResourceOwnerPasswordValidator
	profileProvider                                 func() services.ProfileService
	backChannelLogoutHttpClient                     *http.Client
	backchannelAuthenticationNotificationHttpClient *http.Client
}

func NewServerConfig() *ServerConfig {
	return &ServerConfig{}
}

func (c *ServerConfig) Freeze() {
	c.frozen = true
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

func (c *ServerConfig) BackChannelLogoutHttpClient() *http.Client {
	if c == nil {
		return nil
	}
	return c.backChannelLogoutHttpClient
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
