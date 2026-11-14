// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package memory

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

type MemoryDistributedCache struct {
	mu    sync.Mutex
	items map[string]cacheItem
}

type cacheItem struct {
	value     []byte
	expiresAt time.Time
}

func NewMemoryDistributedCache() *MemoryDistributedCache {
	return &MemoryDistributedCache{items: map[string]cacheItem{}}
}

func (c *MemoryDistributedCache) Get(key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[key]
	if !ok {
		return nil, nil
	}
	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		delete(c.items, key)
		return nil, nil
	}
	return append([]byte(nil), item.value...), nil
}

func (c *MemoryDistributedCache) Set(key string, value []byte, options *services.DistributedCacheEntryOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	item := cacheItem{value: append([]byte(nil), value...)}
	if options != nil {
		item.expiresAt = options.AbsoluteExpiration
	}
	c.items[key] = item
	return nil
}

func (c *MemoryDistributedCache) Remove(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
	return nil
}

// MemoryCorsPolicyService allows an origin when a client lists it among its
// allowed CORS origins. It reads clients through the same origin lookup the
// assembly serves clients from; accept, when non-nil, further decides whether
// a matching client counts (for example, enabled and with a valid
// configuration).
type MemoryCorsPolicyService struct {
	logger *slog.Logger
	lookup storage.ClientOriginLookup
	accept func(context.Context, *models.Client) bool
}

func NewMemoryCorsPolicyService(logger *slog.Logger, lookup storage.ClientOriginLookup, accept func(context.Context, *models.Client) bool) *MemoryCorsPolicyService {
	return &MemoryCorsPolicyService{logger: logger, lookup: lookup, accept: accept}
}

// IsOriginAllowed reports whether origin is allowed. A lookup failure denies
// the origin.
func (s *MemoryCorsPolicyService) IsOriginAllowed(origin string) bool {
	ctx := context.Background()
	clients, err := s.lookup.FindClientsByAllowedOrigin(ctx, origin)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("client origin lookup failed; origin denied", slog.String("origin", origin), slog.String("error", err.Error()))
		}
		return false
	}
	for _, client := range clients {
		if client == nil {
			continue
		}
		if s.accept == nil || s.accept(ctx, client) {
			return true
		}
	}
	return false
}
