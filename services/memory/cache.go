// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package memory

import (
	"log/slog"
	"sync"
	"time"

	"github.com/gonewx/wicket/services"
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

type MemoryCorsPolicyService struct {
	clients []*models.Client
}

func NewMemoryCorsPolicyService(logger *slog.Logger, clients []*models.Client) *MemoryCorsPolicyService {
	return &MemoryCorsPolicyService{clients: clients}
}

func (s *MemoryCorsPolicyService) IsOriginAllowed(origin string) bool {
	for _, client := range s.clients {
		for _, allowed := range client.AllowedCorsOrigins {
			if allowed == origin {
				return true
			}
		}
	}
	return false
}
