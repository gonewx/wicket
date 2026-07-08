// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
)

type BackchannelAuthenticationThrottlingService struct {
	options *config_options.WicketOptions
	clock   services.SystemClock
}

func NewBackchannelAuthenticationThrottlingService(options *config_options.WicketOptions, clock services.SystemClock) *BackchannelAuthenticationThrottlingService {
	return &BackchannelAuthenticationThrottlingService{options: options, clock: clock}
}

func (s *BackchannelAuthenticationThrottlingService) ShouldSlowDown(requestID string, request *storage_models.BackchannelAuthenticationRequest) (bool, error) {
	if request == nil {
		return false, errors.New("backchannel authentication request is required")
	}
	now := s.clock.Now()
	if request.LastPollTime == nil {
		request.LastPollTime = &now
		return false, nil
	}
	interval := request.PollInterval
	if interval <= 0 {
		interval = s.options.BackchannelAuthentication.DefaultPollingInterval
	}
	if request.LastPollTime.Add(time.Duration(interval) * time.Second).After(now) {
		request.PollInterval = interval + s.options.BackchannelAuthentication.SlowDownIntervalIncrement
		request.LastPollTime = &now
		return true, nil
	}
	request.LastPollTime = &now
	return false, nil
}

type BackchannelAuthenticationNotificationService struct {
	client *http.Client
}

func NewBackchannelAuthenticationNotificationService(client *http.Client) *BackchannelAuthenticationNotificationService {
	if client == nil {
		client = http.DefaultClient
	}
	return &BackchannelAuthenticationNotificationService{client: client}
}

func (s *BackchannelAuthenticationNotificationService) Notify(request *storage_models.BackchannelAuthenticationRequest) error {
	if request == nil || request.ClientNotificationEndpoint == "" {
		return nil
	}
	body, err := json.Marshal(map[string]string{"auth_req_id": request.RequestId})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, request.ClientNotificationEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	if request.ClientNotificationToken != "" {
		req.Header.Set("authorization", "Bearer "+request.ClientNotificationToken)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("backchannel authentication notification failed")
	}
	return nil
}
