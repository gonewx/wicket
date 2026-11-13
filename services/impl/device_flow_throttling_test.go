// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	services_memory "github.com/gonewx/wicket/services/memory"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
)

func newThrottlingService(t *testing.T, client *storage_models.Client, interval int) *DistributedDeviceFlowThrottlingService {
	t.Helper()
	clients, err := storage_memory.NewMemoryClientStore([]*storage_models.Client{client})
	if err != nil {
		t.Fatalf("client store: %v", err)
	}
	options := config_options.NewWicketOptions()
	options.DeviceFlow.Interval = interval
	return NewDistributedDeviceFlowThrottlingService(
		services_memory.NewMemoryDistributedCache(),
		clients,
		NewSystemClock(),
		options,
	)
}

func throttlingClient(pollingInterval *int) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = "device.client"
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesDeviceFlow); err != nil {
		panic(err)
	}
	client.PollingInterval = pollingInterval
	return client
}

func throttlingRecord() *storage_models.DeviceCode {
	return &storage_models.DeviceCode{
		ClientId:     "device.client",
		CreationTime: time.Now().UTC(),
		Lifetime:     300,
	}
}

// Two polls of the same device code within the interval: the first is let
// through, the second must slow down. Uses the in-memory cache and the system
// clock the default assembly uses.
func TestDeviceFlowThrottlingSlowsDownSecondPoll(t *testing.T) {
	cases := map[string]struct {
		pollingInterval *int
		optionsInterval int
	}{
		"client polling interval":                  {pollingInterval: intPointer(5), optionsInterval: 0},
		"no client interval falls back to options": {pollingInterval: nil, optionsInterval: 5},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			service := newThrottlingService(t, throttlingClient(tc.pollingInterval), tc.optionsInterval)
			record := throttlingRecord()

			first, err := service.ShouldSlowDown(context.Background(), "device-code-1", record)
			if err != nil || first {
				t.Fatalf("first poll = (%v, %v), want (false, nil)", first, err)
			}
			second, err := service.ShouldSlowDown(context.Background(), "device-code-1", record)
			if err != nil || !second {
				t.Fatalf("second poll = (%v, %v), want (true, nil)", second, err)
			}
		})
	}
}

// Polls of distinct device codes are throttled independently.
func TestDeviceFlowThrottlingIsPerDeviceCode(t *testing.T) {
	service := newThrottlingService(t, throttlingClient(intPointer(5)), 5)
	record := throttlingRecord()

	for _, code := range []string{"device-code-1", "device-code-2"} {
		slow, err := service.ShouldSlowDown(context.Background(), code, record)
		if err != nil || slow {
			t.Fatalf("first poll of %s = (%v, %v), want (false, nil)", code, slow, err)
		}
	}
}

// A poll after the interval has elapsed is let through again.
func TestDeviceFlowThrottlingAllowsPollAfterInterval(t *testing.T) {
	service := newThrottlingService(t, throttlingClient(intPointer(1)), 5)
	record := throttlingRecord()

	if slow, err := service.ShouldSlowDown(context.Background(), "device-code-1", record); err != nil || slow {
		t.Fatalf("first poll = (%v, %v), want (false, nil)", slow, err)
	}
	time.Sleep(1100 * time.Millisecond)
	if slow, err := service.ShouldSlowDown(context.Background(), "device-code-1", record); err != nil || slow {
		t.Fatalf("poll after the interval = (%v, %v), want (false, nil)", slow, err)
	}
}

func intPointer(v int) *int {
	return &v
}
