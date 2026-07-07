// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storage

import (
	"net/url"

	core_models "github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/tokens"
)

// MessageStore persists an opaque message value by generated handle.
// input: message/handle -> behavior: store or retrieve -> output: handle, message, or error.
type MessageStore[T any] interface {
	Write(*messages.Message[*T]) (string, error)
	Read(string) (*messages.Message[*T], error)
}

// AuthorizationParametersMessageStore persists authorize parameters across redirects.
// input: URL values/handle -> behavior: store, read, or delete -> output: handle, values, or error.
type AuthorizationParametersMessageStore interface {
	Write(*messages.Message[url.Values]) (string, error)
	Read(string) (*messages.Message[url.Values], error)
	Delete(string) error
}

// ClientStore loads clients by identifier.
// input: client id -> behavior: find matching enabled or disabled client -> output: client or error.
type ClientStore interface {
	FindClientById(string) (*models.Client, error)
}

// ResourceStore loads API and identity resources by current caller criteria.
// input: names/scopes -> behavior: find matching resources -> output: resources or error.
type ResourceStore interface {
	GetAllEnabledResources() (*models.Resources, error)
	FindResourcesByScope([]string) (*models.Resources, error)
	FindApiResourcesByName([]string) ([]*models.ApiResource, error)
	FindApiScopesByName([]string) ([]*models.ApiScope, error)
	FindIdentityResourcesByScope([]string) ([]*models.IdentityResource, error)
}

// PersistedGrantStore stores grants keyed by persisted grant key and filters.
// input: grant/filter -> behavior: store, query, or remove -> output: grants or error.
type PersistedGrantStore interface {
	Store(*models.PersistedGrant) error
	Get(string) (*models.PersistedGrant, error)
	GetAll(*PersistedGrantFilter) ([]*models.PersistedGrant, error)
	Remove(string) error
	RemoveAll(*PersistedGrantFilter) error
}

// DeviceFlowStore stores device-flow records by device and user codes.
// input: codes/data -> behavior: store, find, update, or remove -> output: data or error.
type DeviceFlowStore interface {
	StoreDeviceAuthorization(string, string, *models.DeviceCode) error
	FindByUserCode(string) (*models.DeviceCode, error)
	FindByDeviceCode(string) (*models.DeviceCode, error)
	UpdateByUserCode(string, *models.DeviceCode) error
	RemoveByDeviceCode(string) error
}

// AuthorizationCodeStore stores authorization codes by generated handle.
// input: code/handle -> behavior: store, find, or remove -> output: handle, code, or error.
type AuthorizationCodeStore interface {
	StoreAuthorizationCode(*models.AuthorizationCode) (string, error)
	GetAuthorizationCode(string) (*models.AuthorizationCode, error)
	RemoveAuthorizationCode(string) error
}

// RefreshTokenStore stores refresh tokens by generated handle.
// input: token/handle -> behavior: store, find, update, or remove -> output: handle, token, or error.
type RefreshTokenStore interface {
	StoreRefreshToken(*models.RefreshToken) (string, error)
	GetRefreshToken(string) (*models.RefreshToken, error)
	UpdateRefreshToken(string, *models.RefreshToken) error
	RemoveRefreshToken(string) error
}

// ReferenceTokenStore stores reference access tokens by generated handle.
// input: token/handle -> behavior: store, find, or remove -> output: handle, token, or error.
type ReferenceTokenStore interface {
	StoreReferenceToken(*models.Token) (string, error)
	GetReferenceToken(string) (*models.Token, error)
	RemoveReferenceToken(string) error
	RemoveReferenceTokens(subjectId, clientId string) error
}

// UserConsentStore stores user consent grants.
// input: consent identity -> behavior: store, find, list, or remove -> output: consent(s) or error.
type UserConsentStore interface {
	StoreUserConsent(*models.Consent) error
	GetUserConsent(subjectId, clientId string) (*models.Consent, error)
	GetAllUserConsents(subjectId string) ([]*models.Consent, error)
	RemoveUserConsent(subjectId, clientId string) error
}

// SigningCredentialStore exposes signing credentials to token services.
// input: none -> behavior: return configured credential -> output: credential or error.
type SigningCredentialStore interface {
	GetSigningCredentials() (*tokens.SigningCredentials, error)
}

// ValidationKeysStore exposes validation keys to token validators.
// input: none -> behavior: return configured validation keys -> output: key list or error.
type ValidationKeysStore interface {
	GetValidationKeys() ([]*core_models.SecurityKeyInfo, error)
}
