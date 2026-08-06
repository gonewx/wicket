// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package storage defines the persistence ports the server consumes. The port
// family serves a single issuer: one server instance owns one set of stores,
// and no port method carries a tenant or issuer dimension. A deployment that
// needs multiple issuers runs one server instance (and one storage set) per
// issuer. Introducing a multi-issuer dimension in the storage layer would be a
// public interface change.
//
// Every port method takes a context as its first parameter. The caller's
// cancellation and deadline propagate to the adapter; an adapter must not
// fabricate its own context.Background() or override the caller's timeout.
// Read methods report a missing record with a sentinel error (ErrNotFound for
// this package's port family) and never with a nil record and nil error, so a
// host can distinguish "record absent" from "infrastructure failure". List
// methods return an empty slice, not the sentinel.
//
// Stores never judge expiry: a read returns the record whether or not it is
// expired, and adapters must not filter on their own clock (for example by
// appending an expires_at comparison to a query). Expiry is judged on the core
// side. Data with a lifecycle exposes a caller-driven one-shot reclamation
// method, RemoveExpired, which returns how many records were removed; it
// reclaims space only and carries no correctness responsibility. Ports whose
// data has no server-side lifecycle (message stores, configuration data, key
// records) carry no reclamation method.
package storage

import (
	"context"
	"errors"
	"net/url"
	"time"

	core_models "github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/tokens"
)

// ErrNotFound reports that a single-record read missed. It is the port family's
// sentinel for "record absent", distinct from any infrastructure error.
var ErrNotFound = errors.New("storage: record not found")

// MessageStore persists an opaque message value by generated handle. Message
// data is either self-contained in a protected payload or held by the client,
// so the store keeps no server-side lifecycle and carries no reclamation
// method.
type MessageStore[T any] interface {
	Write(ctx context.Context, message *messages.Message[*T]) (string, error)
	Read(ctx context.Context, handle string) (*messages.Message[*T], error)
}

// AuthorizationParametersMessageStore persists authorize parameters across
// redirects. Message data is either self-contained in a protected payload or
// held by the client, so the store keeps no server-side lifecycle and carries
// no reclamation method.
type AuthorizationParametersMessageStore interface {
	Write(ctx context.Context, message *messages.Message[url.Values]) (string, error)
	Read(ctx context.Context, handle string) (*messages.Message[url.Values], error)
	Delete(ctx context.Context, handle string) error
}

// ClientStore loads clients by identifier. Client records are configuration
// data without a lifecycle, so the store carries no reclamation method.
type ClientStore interface {
	FindClientById(ctx context.Context, clientId string) (*models.Client, error)
}

// ResourceStore loads API and identity resources by current caller criteria.
// Resource records are configuration data without a lifecycle, so the store
// carries no reclamation method.
type ResourceStore interface {
	GetAllEnabledResources(ctx context.Context) (*models.Resources, error)
	FindResourcesByScope(ctx context.Context, scopes []string) (*models.Resources, error)
	FindApiResourcesByName(ctx context.Context, names []string) ([]*models.ApiResource, error)
	FindApiScopesByName(ctx context.Context, names []string) ([]*models.ApiScope, error)
	FindIdentityResourcesByScope(ctx context.Context, scopes []string) ([]*models.IdentityResource, error)
}

// PersistedGrantStore stores grants keyed by persisted grant key and filters.
type PersistedGrantStore interface {
	Store(ctx context.Context, grant *models.PersistedGrant) error
	Get(ctx context.Context, key string) (*models.PersistedGrant, error)
	GetAll(ctx context.Context, filter *PersistedGrantFilter) ([]*models.PersistedGrant, error)
	Remove(ctx context.Context, key string) error
	RemoveAll(ctx context.Context, filter *PersistedGrantFilter) error
	// RemoveExpired removes grants whose Expiration is set and precedes cutoff,
	// returning how many were removed. It reclaims space only; expiry judgement
	// remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// DeviceFlowStore stores device-flow records by device and user codes.
type DeviceFlowStore interface {
	StoreDeviceAuthorization(ctx context.Context, deviceCode string, userCode string, data *models.DeviceCode) error
	FindByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error)
	FindByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error)
	UpdateByUserCode(ctx context.Context, userCode string, data *models.DeviceCode) error
	RemoveByDeviceCode(ctx context.Context, deviceCode string) error
	// RemoveExpired removes device-flow records whose creation time plus
	// lifetime precedes cutoff, returning how many were removed. It reclaims
	// space only; expiry judgement remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// BackchannelAuthenticationRequestStore stores CIBA request state by opaque auth_req_id.
type BackchannelAuthenticationRequestStore interface {
	StoreBackchannelAuthenticationRequest(ctx context.Context, requestID string, data *models.BackchannelAuthenticationRequest) error
	FindBackchannelAuthenticationRequest(ctx context.Context, requestID string) (*models.BackchannelAuthenticationRequest, error)
	UpdateBackchannelAuthenticationRequest(ctx context.Context, requestID string, data *models.BackchannelAuthenticationRequest) error
	RemoveBackchannelAuthenticationRequest(ctx context.Context, requestID string) error
	// RemoveExpired removes CIBA requests whose ExpirationTime precedes cutoff,
	// returning how many were removed. It reclaims space only; expiry judgement
	// remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// AuthorizationCodeStore stores authorization codes by generated handle.
type AuthorizationCodeStore interface {
	StoreAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) (string, error)
	GetAuthorizationCode(ctx context.Context, handle string) (*models.AuthorizationCode, error)
	RemoveAuthorizationCode(ctx context.Context, handle string) error
	// RemoveExpired removes codes whose creation time plus lifetime precedes
	// cutoff, returning how many were removed. It reclaims space only; expiry
	// judgement remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// RefreshTokenStore stores refresh tokens by generated handle.
type RefreshTokenStore interface {
	StoreRefreshToken(ctx context.Context, token *models.RefreshToken) (string, error)
	GetRefreshToken(ctx context.Context, handle string) (*models.RefreshToken, error)
	UpdateRefreshToken(ctx context.Context, handle string, token *models.RefreshToken) error
	RemoveRefreshToken(ctx context.Context, handle string) error
	// RemoveExpired removes tokens whose creation time plus lifetime precedes
	// cutoff, returning how many were removed. It reclaims space only; expiry
	// judgement remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// ReferenceTokenStore stores reference access tokens by generated handle.
type ReferenceTokenStore interface {
	StoreReferenceToken(ctx context.Context, token *models.Token) (string, error)
	GetReferenceToken(ctx context.Context, handle string) (*models.Token, error)
	RemoveReferenceToken(ctx context.Context, handle string) error
	RemoveReferenceTokens(ctx context.Context, subjectId, clientId string) error
	// RemoveExpired removes tokens whose creation time plus lifetime precedes
	// cutoff, returning how many were removed. It reclaims space only; expiry
	// judgement remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// UserConsentStore stores user consent grants.
type UserConsentStore interface {
	StoreUserConsent(ctx context.Context, consent *models.Consent) error
	GetUserConsent(ctx context.Context, subjectId, clientId string) (*models.Consent, error)
	GetAllUserConsents(ctx context.Context, subjectId string) ([]*models.Consent, error)
	RemoveUserConsent(ctx context.Context, subjectId, clientId string) error
	// RemoveExpired removes consents whose Expiration is set and precedes
	// cutoff, returning how many were removed. It reclaims space only; expiry
	// judgement remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// SigningCredentialStore exposes signing credentials to token services.
// Credentials are configuration data without a lifecycle, so the store carries
// no reclamation method.
type SigningCredentialStore interface {
	GetSigningCredentials(ctx context.Context) (*tokens.SigningCredentials, error)
}

// ValidationKeysStore exposes validation keys to token validators. Keys are
// configuration data without a lifecycle, so the store carries no reclamation
// method.
type ValidationKeysStore interface {
	GetValidationKeys(ctx context.Context) ([]*core_models.SecurityKeyInfo, error)
}
