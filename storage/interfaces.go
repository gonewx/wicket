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

// ErrDuplicateHandle reports that an insert-only write collided with an
// existing handle. Insert-only stores never overwrite; a collision means the
// caller's generated handle is not unique, which the caller must treat as an
// infrastructure defect, not a protocol event.
var ErrDuplicateHandle = errors.New("storage: duplicate handle")

// ErrVersionConflict reports that an optimistic-concurrency update carried an
// expected version that does not match the stored version. The caller must
// reload the record and decide whether to retry or fail; a store never
// resolves the conflict itself.
var ErrVersionConflict = errors.New("storage: version conflict")

// ErrInvalidClientConfiguration reports that a client record was found but its
// configuration failed the runtime configuration validation (including a
// configuration that relies on a feature the assembly does not enable). Read
// paths treat it like an absent client: the client cannot be used, and the
// failure is not an infrastructure error.
var ErrInvalidClientConfiguration = errors.New("storage: invalid client configuration")

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

// ClientRegistrationStore keeps registered clients and serves them to the
// read path from the same data: FindClientById returns the client of a
// registered record. A host that injects it implements ClientOriginLookup on
// the same value, so CORS decisions read the same records.
//
// The record of a client is keyed by Client.ClientId. An adapter persists the
// client as the opaque bytes of EncodeClient and restores it with
// DecodeClient, next to the visible fields of the record (client id,
// revision, registration access token digest, registration time).
//
// Registration is insert-only: a client id that is registered, or that was
// registered and removed, fails with ErrDuplicateHandle and leaves the stored
// data unchanged. Removal leaves a tombstone, so a removed client id is never
// registered again; reads, updates and removals of a removed client id report
// ErrNotFound.
//
// The store assigns revisions. A registration commits revision 1; an update
// or removal carries the revision the caller read and fails with
// ErrVersionConflict, leaving the record unchanged, when it does not match the
// stored one; a successful update commits the expected revision plus one.
// Write methods return the committed revision and ignore the Revision of the
// record passed in. The caller resolves a conflict by reloading the record.
//
// Registered clients have no server-side lifecycle, so the store carries no
// reclamation method. It offers no lookup by registration access token digest
// and no unfiltered enumeration.
type ClientRegistrationStore interface {
	ClientStore
	// RegisterClient stores a new registration and returns its revision, 1.
	RegisterClient(ctx context.Context, registration *models.ClientRegistration) (int, error)
	// FindClientRegistration returns the registration of a client id, or
	// ErrNotFound.
	FindClientRegistration(ctx context.Context, clientId string) (*models.ClientRegistration, error)
	// UpdateClientRegistration replaces the registration of
	// registration.Client.ClientId when its stored revision equals
	// expectedRevision, and returns the committed revision.
	UpdateClientRegistration(ctx context.Context, registration *models.ClientRegistration, expectedRevision int) (int, error)
	// RemoveClientRegistration removes the registration of a client id when
	// its stored revision equals expectedRevision, and leaves a tombstone.
	RemoveClientRegistration(ctx context.Context, clientId string, expectedRevision int) error
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
	// Store writes a grant under its Key. The write is an upsert: storing a
	// grant whose Key already exists replaces the stored record, because the
	// key is a caller-chosen natural key whose data evolves over the grant's
	// lifecycle.
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
	// StoreDeviceAuthorization writes a record under the caller-supplied
	// device and user codes. The write is insert-only: either code already
	// being present fails with ErrDuplicateHandle and the stored records are
	// left unchanged.
	StoreDeviceAuthorization(ctx context.Context, deviceCode string, userCode string, data *models.DeviceCode) error
	FindByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error)
	FindByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error)
	// UpdateByUserCode replaces the record for a state migration (for example
	// marking the flow consumed). It is not version-guarded: the one-shot
	// semantics of the flow are enforced by state fields and removal, not by
	// an optimistic-concurrency marker.
	UpdateByUserCode(ctx context.Context, userCode string, data *models.DeviceCode) error
	RemoveByDeviceCode(ctx context.Context, deviceCode string) error
	// RemoveExpired removes device-flow records whose creation time plus
	// lifetime precedes cutoff, returning how many were removed. It reclaims
	// space only; expiry judgement remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// BackchannelAuthenticationRequestStore stores CIBA request state by opaque auth_req_id.
type BackchannelAuthenticationRequestStore interface {
	// StoreBackchannelAuthenticationRequest writes a record under the
	// caller-supplied request id. The write is insert-only: a request id that
	// already exists fails with ErrDuplicateHandle and the stored record is
	// left unchanged.
	StoreBackchannelAuthenticationRequest(ctx context.Context, requestID string, data *models.BackchannelAuthenticationRequest) error
	FindBackchannelAuthenticationRequest(ctx context.Context, requestID string) (*models.BackchannelAuthenticationRequest, error)
	// UpdateBackchannelAuthenticationRequest replaces the record for a state
	// migration (for example marking the request consumed). It is not
	// version-guarded: the one-shot semantics of the flow are enforced by
	// state fields and removal, not by an optimistic-concurrency marker.
	UpdateBackchannelAuthenticationRequest(ctx context.Context, requestID string, data *models.BackchannelAuthenticationRequest) error
	RemoveBackchannelAuthenticationRequest(ctx context.Context, requestID string) error
	// RemoveExpired removes CIBA requests whose ExpirationTime precedes cutoff,
	// returning how many were removed. It reclaims space only; expiry judgement
	// remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// AuthorizationCodeStore stores authorization codes by caller-supplied handle.
type AuthorizationCodeStore interface {
	// StoreAuthorizationCode writes a code under the caller-supplied handle.
	// The write is insert-only: a handle that already exists fails with
	// ErrDuplicateHandle and the stored record is left unchanged.
	StoreAuthorizationCode(ctx context.Context, handle string, code *models.AuthorizationCode) error
	// GetAuthorizationCode returns an independent copy of the stored code.
	// The caller may mutate the returned value without affecting the store.
	GetAuthorizationCode(ctx context.Context, handle string) (*models.AuthorizationCode, error)
	RemoveAuthorizationCode(ctx context.Context, handle string) error
	// RemoveExpired removes codes whose creation time plus lifetime precedes
	// cutoff, returning how many were removed. It reclaims space only; expiry
	// judgement remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// RefreshTokenStore stores refresh tokens by caller-supplied handle.
type RefreshTokenStore interface {
	// StoreRefreshToken writes a token under the caller-supplied handle.
	// The write is insert-only: a handle that already exists fails with
	// ErrDuplicateHandle and the stored record is left unchanged. The stored
	// copy carries version 1, and the caller's token.Version is written back
	// with the same value.
	StoreRefreshToken(ctx context.Context, handle string, token *models.RefreshToken) error
	// GetRefreshToken returns an independent copy of the stored token.
	// The caller may mutate the returned value without affecting the store.
	GetRefreshToken(ctx context.Context, handle string) (*models.RefreshToken, error)
	// UpdateRefreshToken replaces the stored token under an optimistic
	// concurrency check: the update succeeds only when the stored version
	// equals expectedVersion, and the new stored copy carries version
	// expectedVersion+1, written back to the caller's token.Version. A
	// mismatch fails with ErrVersionConflict and the stored record is left
	// unchanged.
	UpdateRefreshToken(ctx context.Context, handle string, token *models.RefreshToken, expectedVersion int) error
	RemoveRefreshToken(ctx context.Context, handle string) error
	// RemoveExpired removes tokens whose creation time plus lifetime precedes
	// cutoff, returning how many were removed. It reclaims space only; expiry
	// judgement remains on the core side.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}

// ReferenceTokenStore stores reference access tokens by caller-supplied handle.
type ReferenceTokenStore interface {
	// StoreReferenceToken writes a token under the caller-supplied handle.
	// The write is insert-only: a handle that already exists fails with
	// ErrDuplicateHandle and the stored record is left unchanged.
	StoreReferenceToken(ctx context.Context, handle string, token *models.Token) error
	// GetReferenceToken returns an independent copy of the stored token.
	// The caller may mutate the returned value without affecting the store.
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
	// StoreUserConsent writes a consent under the caller-supplied
	// subject+client natural key. The write is an upsert: storing a consent
	// for a subject/client pair that already exists replaces the stored
	// record, because repeated authorization decisions naturally overwrite
	// the earlier decision.
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
