// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import storage_models "github.com/gonewx/wicket/storage/models"

type TestDeviceFlowThrottlingService struct {
	shouldSlownDown bool
}

func NewTestDeviceFlowThrottlingService(shouldSlownDown bool) *TestDeviceFlowThrottlingService {
	{
		return &TestDeviceFlowThrottlingService{
			shouldSlownDown: shouldSlownDown,
		}
	}
}

func (s *TestDeviceFlowThrottlingService) ShouldSlowDown(deviceCode string, details *storage_models.DeviceCode) (bool, error) {
	return s.shouldSlownDown, nil
}
