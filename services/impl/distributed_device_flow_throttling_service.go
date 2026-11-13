// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"fmt"
	"time"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

const KeyPrefix = "devicecode_"

// DistributedDeviceFlowThrottlingService The default device flow throttling service using DistributedCache
type DistributedDeviceFlowThrottlingService struct {
	cache       services.DistributedCache
	clientStore storage.ClientStore
	clock       services.SystemClock
	options     *config_options.WicketOptions
}

func NewDistributedDeviceFlowThrottlingService(
	cache services.DistributedCache,
	clientStore storage.ClientStore,
	clock services.SystemClock,
	options *config_options.WicketOptions,
) *DistributedDeviceFlowThrottlingService {
	return &DistributedDeviceFlowThrottlingService{
		cache:       cache,
		clientStore: clientStore,
		clock:       clock,
		options:     options,
	}
}

// Decides if the requesting client and device code needs to slow down.
func (s *DistributedDeviceFlowThrottlingService) ShouldSlowDown(ctx context.Context, deviceCode string, details *storage_models.DeviceCode) (bool, error) {
	if deviceCode == "" {
		return false, fmt.Errorf("deviceCode is empty")
	}

	key := KeyPrefix + deviceCode
	options := &services.DistributedCacheEntryOptions{
		AbsoluteExpiration: s.clock.Now().Add(time.Duration(details.Lifetime) * time.Second),
	}

	lastSeenAsString := extensions.DistributedCacheGetString(s.cache, key)

	// record new
	if lastSeenAsString == "" {
		extensions.DistributedCacheSetString(s.cache, key, s.clock.Now().Format(time.RFC3339Nano), options)
		return false, nil
	}

	// check interval
	lastSeen, err := time.Parse(time.RFC3339Nano, lastSeenAsString)
	if err == nil {
		lastSeen = lastSeen.UTC()

		client, err := extensions.FindEnabledClientById(ctx, s.clientStore, details.ClientId)
		if err != nil {
			return false, err
		}

		interval := 0
		if client != nil && client.PollingInterval != nil {
			interval = *client.PollingInterval
		} else {
			interval = s.options.DeviceFlow.Interval
		}

		if s.clock.Now().Sub(lastSeen) < time.Duration(interval)*time.Second {
			extensions.DistributedCacheSetString(s.cache, key, s.clock.Now().Format(time.RFC3339Nano), options)
			return true, nil
		}
	}

	// store current and continue
	extensions.DistributedCacheSetString(s.cache, key, s.clock.Now().Format(time.RFC3339Nano), options)
	return false, nil
}
