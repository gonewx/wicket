// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package di

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/services"
	services_memory "github.com/gonewx/wicket/services/memory"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// warnFallback reports a store seam that fell back to its in-memory
// implementation so a host that forgot to inject the store gets a signal
// instead of silent per-process state.
func warnFallback(logger *slog.Logger, store string) {
	if logger == nil {
		return
	}
	logger.Warn(fmt.Sprintf("store %s not injected by host; falling back to in-memory implementation", store))
}

// requireInjectedOrFallback fails fast when the host froze the configuration
// without injecting the store and without declaring the in-memory fallback.
// The normal path is Freeze()'s assembly-time validation; this guards the same
// contract at first use for configurations that skip Freeze.
func requireInjectedOrFallback(cfg *ServerConfig, store string) {
	if cfg != nil && cfg.Frozen() && !cfg.allowInMemoryFallback {
		panic(fmt.Sprintf("store seam %q not injected by host and in-memory fallback not declared", store))
	}
}

type lazyPersistedGrantStore struct {
	cfg    *ServerConfig
	logger *slog.Logger
	once   sync.Once
	impl   storage.PersistedGrantStore
}

func (s *lazyPersistedGrantStore) store() storage.PersistedGrantStore {
	s.once.Do(func() {
		s.impl = s.cfg.PersistedGrantStore()
		if s.impl == nil {
			requireInjectedOrFallback(s.cfg, "persisted grant store")
			warnFallback(s.logger, "persisted grant store")
			s.impl = storage_memory.NewMemoryPersistedGrantStore()
		}
	})
	return s.impl
}

func (s *lazyPersistedGrantStore) Store(ctx context.Context, grant *storage_models.PersistedGrant) error {
	return s.store().Store(ctx, grant)
}

func (s *lazyPersistedGrantStore) Get(ctx context.Context, key string) (*storage_models.PersistedGrant, error) {
	return s.store().Get(ctx, key)
}

func (s *lazyPersistedGrantStore) GetAll(ctx context.Context, filter *storage.PersistedGrantFilter) ([]*storage_models.PersistedGrant, error) {
	return s.store().GetAll(ctx, filter)
}

func (s *lazyPersistedGrantStore) Remove(ctx context.Context, key string) error {
	return s.store().Remove(ctx, key)
}

func (s *lazyPersistedGrantStore) RemoveAll(ctx context.Context, filter *storage.PersistedGrantFilter) error {
	return s.store().RemoveAll(ctx, filter)
}

func (s *lazyPersistedGrantStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().RemoveExpired(ctx, cutoff)
}

type lazyDeviceFlowStore struct {
	cfg    *ServerConfig
	logger *slog.Logger
	once   sync.Once
	impl   storage.DeviceFlowStore
}

func (s *lazyDeviceFlowStore) store() storage.DeviceFlowStore {
	s.once.Do(func() {
		s.impl = s.cfg.DeviceFlowStore()
		if s.impl == nil {
			requireInjectedOrFallback(s.cfg, "device flow store")
			warnFallback(s.logger, "device flow store")
			s.impl = storage_memory.NewMemoryDeviceFlowStore()
		}
	})
	return s.impl
}

func (s *lazyDeviceFlowStore) StoreDeviceAuthorization(ctx context.Context, deviceCode string, userCode string, data *storage_models.DeviceCode) error {
	return s.store().StoreDeviceAuthorization(ctx, deviceCode, userCode, data)
}

func (s *lazyDeviceFlowStore) FindByUserCode(ctx context.Context, userCode string) (*storage_models.DeviceCode, error) {
	return s.store().FindByUserCode(ctx, userCode)
}

func (s *lazyDeviceFlowStore) FindByDeviceCode(ctx context.Context, deviceCode string) (*storage_models.DeviceCode, error) {
	return s.store().FindByDeviceCode(ctx, deviceCode)
}

func (s *lazyDeviceFlowStore) UpdateByUserCode(ctx context.Context, userCode string, data *storage_models.DeviceCode) error {
	return s.store().UpdateByUserCode(ctx, userCode, data)
}

func (s *lazyDeviceFlowStore) RemoveByDeviceCode(ctx context.Context, deviceCode string) error {
	return s.store().RemoveByDeviceCode(ctx, deviceCode)
}

func (s *lazyDeviceFlowStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().RemoveExpired(ctx, cutoff)
}

type lazyBackchannelAuthenticationRequestStore struct {
	cfg    *ServerConfig
	logger *slog.Logger
	once   sync.Once
	impl   storage.BackchannelAuthenticationRequestStore
}

func (s *lazyBackchannelAuthenticationRequestStore) store() storage.BackchannelAuthenticationRequestStore {
	s.once.Do(func() {
		s.impl = s.cfg.BackchannelAuthenticationRequestStore()
		if s.impl == nil {
			requireInjectedOrFallback(s.cfg, "backchannel authentication request store")
			warnFallback(s.logger, "backchannel authentication request store")
			s.impl = storage_memory.NewMemoryBackchannelAuthenticationRequestStore()
		}
	})
	return s.impl
}

func (s *lazyBackchannelAuthenticationRequestStore) StoreBackchannelAuthenticationRequest(ctx context.Context, requestID string, data *storage_models.BackchannelAuthenticationRequest) error {
	return s.store().StoreBackchannelAuthenticationRequest(ctx, requestID, data)
}

func (s *lazyBackchannelAuthenticationRequestStore) FindBackchannelAuthenticationRequest(ctx context.Context, requestID string) (*storage_models.BackchannelAuthenticationRequest, error) {
	return s.store().FindBackchannelAuthenticationRequest(ctx, requestID)
}

func (s *lazyBackchannelAuthenticationRequestStore) UpdateBackchannelAuthenticationRequest(ctx context.Context, requestID string, data *storage_models.BackchannelAuthenticationRequest) error {
	return s.store().UpdateBackchannelAuthenticationRequest(ctx, requestID, data)
}

func (s *lazyBackchannelAuthenticationRequestStore) RemoveBackchannelAuthenticationRequest(ctx context.Context, requestID string) error {
	return s.store().RemoveBackchannelAuthenticationRequest(ctx, requestID)
}

func (s *lazyBackchannelAuthenticationRequestStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().RemoveExpired(ctx, cutoff)
}

type lazyAuthorizationCodeStore struct {
	cfg    *ServerConfig
	logger *slog.Logger
	once   sync.Once
	impl   storage.AuthorizationCodeStore
}

func (s *lazyAuthorizationCodeStore) store() storage.AuthorizationCodeStore {
	s.once.Do(func() {
		s.impl = s.cfg.AuthorizationCodeStore()
		if s.impl == nil {
			requireInjectedOrFallback(s.cfg, "authorization code store")
			warnFallback(s.logger, "authorization code store")
			s.impl = storage_impl.NewAuthorizationCodeStore()
		}
	})
	return s.impl
}

func (s *lazyAuthorizationCodeStore) StoreAuthorizationCode(ctx context.Context, handle string, code *storage_models.AuthorizationCode) error {
	return s.store().StoreAuthorizationCode(ctx, handle, code)
}

func (s *lazyAuthorizationCodeStore) GetAuthorizationCode(ctx context.Context, handle string) (*storage_models.AuthorizationCode, error) {
	return s.store().GetAuthorizationCode(ctx, handle)
}

func (s *lazyAuthorizationCodeStore) RemoveAuthorizationCode(ctx context.Context, handle string) error {
	return s.store().RemoveAuthorizationCode(ctx, handle)
}

func (s *lazyAuthorizationCodeStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().RemoveExpired(ctx, cutoff)
}

type lazyRefreshTokenStore struct {
	cfg    *ServerConfig
	logger *slog.Logger
	once   sync.Once
	impl   storage.RefreshTokenStore
}

func (s *lazyRefreshTokenStore) store() storage.RefreshTokenStore {
	s.once.Do(func() {
		s.impl = s.cfg.RefreshTokenStore()
		if s.impl == nil {
			requireInjectedOrFallback(s.cfg, "refresh token store")
			warnFallback(s.logger, "refresh token store")
			s.impl = storage_impl.NewRefreshTokenStore()
		}
	})
	return s.impl
}

func (s *lazyRefreshTokenStore) StoreRefreshToken(ctx context.Context, handle string, token *storage_models.RefreshToken) error {
	return s.store().StoreRefreshToken(ctx, handle, token)
}

func (s *lazyRefreshTokenStore) GetRefreshToken(ctx context.Context, handle string) (*storage_models.RefreshToken, error) {
	return s.store().GetRefreshToken(ctx, handle)
}

func (s *lazyRefreshTokenStore) UpdateRefreshToken(ctx context.Context, handle string, token *storage_models.RefreshToken, expectedVersion int) error {
	return s.store().UpdateRefreshToken(ctx, handle, token, expectedVersion)
}

func (s *lazyRefreshTokenStore) RemoveRefreshToken(ctx context.Context, handle string) error {
	return s.store().RemoveRefreshToken(ctx, handle)
}

func (s *lazyRefreshTokenStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().RemoveExpired(ctx, cutoff)
}

type lazyReferenceTokenStore struct {
	cfg    *ServerConfig
	logger *slog.Logger
	once   sync.Once
	impl   storage.ReferenceTokenStore
}

func (s *lazyReferenceTokenStore) store() storage.ReferenceTokenStore {
	s.once.Do(func() {
		s.impl = s.cfg.ReferenceTokenStore()
		if s.impl == nil {
			requireInjectedOrFallback(s.cfg, "reference token store")
			warnFallback(s.logger, "reference token store")
			s.impl = storage_impl.NewReferenceTokenStore()
		}
	})
	return s.impl
}

func (s *lazyReferenceTokenStore) StoreReferenceToken(ctx context.Context, handle string, token *storage_models.Token) error {
	return s.store().StoreReferenceToken(ctx, handle, token)
}

func (s *lazyReferenceTokenStore) GetReferenceToken(ctx context.Context, handle string) (*storage_models.Token, error) {
	return s.store().GetReferenceToken(ctx, handle)
}

func (s *lazyReferenceTokenStore) RemoveReferenceToken(ctx context.Context, handle string) error {
	return s.store().RemoveReferenceToken(ctx, handle)
}

func (s *lazyReferenceTokenStore) RemoveReferenceTokens(ctx context.Context, subjectId, clientId string) error {
	return s.store().RemoveReferenceTokens(ctx, subjectId, clientId)
}

func (s *lazyReferenceTokenStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().RemoveExpired(ctx, cutoff)
}

type lazyUserConsentStore struct {
	cfg    *ServerConfig
	logger *slog.Logger
	once   sync.Once
	impl   storage.UserConsentStore
}

func (s *lazyUserConsentStore) store() storage.UserConsentStore {
	s.once.Do(func() {
		s.impl = s.cfg.UserConsentStore()
		if s.impl == nil {
			requireInjectedOrFallback(s.cfg, "user consent store")
			warnFallback(s.logger, "user consent store")
			s.impl = storage_impl.NewUserConsentStore()
		}
	})
	return s.impl
}

func (s *lazyUserConsentStore) StoreUserConsent(ctx context.Context, consent *storage_models.Consent) error {
	return s.store().StoreUserConsent(ctx, consent)
}

func (s *lazyUserConsentStore) GetUserConsent(ctx context.Context, subjectId, clientId string) (*storage_models.Consent, error) {
	return s.store().GetUserConsent(ctx, subjectId, clientId)
}

func (s *lazyUserConsentStore) GetAllUserConsents(ctx context.Context, subjectId string) ([]*storage_models.Consent, error) {
	return s.store().GetAllUserConsents(ctx, subjectId)
}

func (s *lazyUserConsentStore) RemoveUserConsent(ctx context.Context, subjectId, clientId string) error {
	return s.store().RemoveUserConsent(ctx, subjectId, clientId)
}

func (s *lazyUserConsentStore) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().RemoveExpired(ctx, cutoff)
}

type lazySessionStore struct {
	cfg    *ServerConfig
	logger *slog.Logger
	clock  services.SystemClock
	once   sync.Once
	impl   sessionpkg.Store
}

func (s *lazySessionStore) store() sessionpkg.Store {
	s.once.Do(func() {
		s.impl = s.cfg.SessionStore()
		if s.impl == nil {
			requireInjectedOrFallback(s.cfg, "session store")
			warnFallback(s.logger, "session store")
			s.impl = sessionpkg.NewMemoryStore(s.clock)
		}
	})
	return s.impl
}

func (s *lazySessionStore) GetSession(ctx context.Context, sessionID string) (*sessionpkg.Record, error) {
	return s.store().GetSession(ctx, sessionID)
}

func (s *lazySessionStore) CreateSession(ctx context.Context, session *sessionpkg.Record) error {
	return s.store().CreateSession(ctx, session)
}

func (s *lazySessionStore) UpdateSession(ctx context.Context, session *sessionpkg.Record) error {
	return s.store().UpdateSession(ctx, session)
}

func (s *lazySessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	return s.store().DeleteSession(ctx, sessionID)
}

func (s *lazySessionStore) GetSessionsBySubjectID(ctx context.Context, subjectID string) ([]*sessionpkg.Record, error) {
	return s.store().GetSessionsBySubjectID(ctx, subjectID)
}

func (s *lazySessionStore) DeleteSessionsBySubjectID(ctx context.Context, subjectID string) (int, error) {
	return s.store().DeleteSessionsBySubjectID(ctx, subjectID)
}

func (s *lazySessionStore) AddClientID(ctx context.Context, sessionID, clientID string) error {
	return s.store().AddClientID(ctx, sessionID, clientID)
}

func (s *lazySessionStore) DeleteExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return s.store().DeleteExpired(ctx, cutoff)
}

type lazyDistributedCache struct {
	cfg    *ServerConfig
	logger *slog.Logger
	once   sync.Once
	impl   services.DistributedCache
}

func (s *lazyDistributedCache) store() services.DistributedCache {
	s.once.Do(func() {
		s.impl = s.cfg.DistributedCache()
		if s.impl == nil {
			requireInjectedOrFallback(s.cfg, "distributed cache")
			warnFallback(s.logger, "distributed cache")
			s.impl = services_memory.NewMemoryDistributedCache()
		}
	})
	return s.impl
}

func (s *lazyDistributedCache) Get(key string) ([]byte, error) {
	return s.store().Get(key)
}

func (s *lazyDistributedCache) Set(key string, value []byte, options *services.DistributedCacheEntryOptions) error {
	return s.store().Set(key, value, options)
}

func (s *lazyDistributedCache) Remove(key string) error {
	return s.store().Remove(key)
}

type lazyRecordStore struct {
	cfg    *ServerConfig
	logger *slog.Logger
	once   sync.Once
	impl   keymgmt.RecordStore
}

func (s *lazyRecordStore) store() keymgmt.RecordStore {
	s.once.Do(func() {
		s.impl = s.cfg.RecordStore()
		if s.impl == nil {
			requireInjectedOrFallback(s.cfg, "key record store")
			warnFallback(s.logger, "key record store")
			s.impl = keymgmt.NewMemoryRecordStore()
		}
	})
	return s.impl
}

func (s *lazyRecordStore) List(ctx context.Context) ([]*keymgmt.Record, error) {
	return s.store().List(ctx)
}

func (s *lazyRecordStore) Get(ctx context.Context, handle string) (*keymgmt.Record, error) {
	return s.store().Get(ctx, handle)
}

func (s *lazyRecordStore) Create(ctx context.Context, record *keymgmt.Record) error {
	return s.store().Create(ctx, record)
}

func (s *lazyRecordStore) Update(ctx context.Context, record *keymgmt.Record, expectedVersion uint64) error {
	return s.store().Update(ctx, record, expectedVersion)
}

func (s *lazyRecordStore) Delete(ctx context.Context, handle string) error {
	return s.store().Delete(ctx, handle)
}
