// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package extensions

import "github.com/gonewx/wicket/services"

func DistributedCacheGetString(cache services.DistributedCache, key string) string {
	if cache == nil {
		return ""
	}
	data, err := cache.Get(key)
	if err != nil {
		return ""
	}
	return string(data)
}

func DistributedCacheSetString(cache services.DistributedCache, key string, value string, options *services.DistributedCacheEntryOptions) {
	if cache != nil {
		_ = cache.Set(key, []byte(value), options)
	}
}
