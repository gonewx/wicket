// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"log/slog"
	urlpkg "net/url"
	"strings"

	"github.com/gonewx/wicket"

	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
	storage "github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
)

// LogoutNotificationService Default implementation of logout notification service.
type LogoutNotificationService struct {
	clientStore       storage.ClientStore
	issuerNameService services.IssuerNameService
	logger            *slog.Logger
}

func NewLogoutNotificationService(clientStore storage.ClientStore, issuerNameService services.IssuerNameService, logger *slog.Logger) *LogoutNotificationService {
	return &LogoutNotificationService{
		clientStore:       clientStore,
		issuerNameService: issuerNameService,
		logger:            logger,
	}
}

// GetFrontChannelLogoutNotificationsUrls Builds the URLs needed for front-channel logout notification.
func (s *LogoutNotificationService) GetFrontChannelLogoutNotificationsUrls(ctx *contexts.LogoutNotificationContext) ([]string, error) {
	frontChannelUrls := make([]string, 0)
	for _, clientId := range ctx.ClientIds {
		client, err := extensions.FindEnabledClientById(s.clientStore, clientId)

		if err != nil || client == nil {
			continue
		}

		if client.FrontChannelLogoutUri == "" {
			continue
		}

		url, err := urlpkg.Parse(client.FrontChannelLogoutUri)
		if err != nil {
			s.logger.Debug("FrontChannelLogoutUri parse fail", slog.String("FrontChannelLogoutUri", client.FrontChannelLogoutUri))
			continue
		}

		q := url.Query()

		// add session id if required
		if client.ProtocolType == gois.ProtocolTypesOpenIdConnect {
			if client.FrontChannelLogoutSessionRequired {
				q.Set(gois.EndSessionRequestSid, ctx.SessionId)
				q.Set(gois.EndSessionRequestIssuer, s.issuerNameService.GetCurrent())
				url.RawQuery = q.Encode()
			}
		} else {
			if client.ProtocolType == gois.ProtocolTypesSaml2p {
				q.Set(gois.CleanRoomProtocolGapSignOutLogoutUriParameterName, gois.CleanRoomProtocolGapSignOutLogoutUriParameterValue)
				url.RawQuery = q.Encode()
			}
		}

		frontChannelUrls = append(frontChannelUrls, url.String())
	}

	if len(frontChannelUrls) > 0 {
		msg := strings.Join(frontChannelUrls, ", ")
		s.logger.Debug("Client front-channel logout URLs", slog.String("msg", msg))
	} else {
		s.logger.Debug("No client front-channel logout URLs")

	}
	return frontChannelUrls, nil
}

// GetBackchannelLogoutNotifications Builds the http back-channel logout request data for the collection of clients.
func (s *LogoutNotificationService) GetBackchannelLogoutNotifications(ctx *contexts.LogoutNotificationContext) ([]*services.BackchannelLogoutRequest, error) {
	backChannelLogouts := make([]*services.BackchannelLogoutRequest, 0)
	for _, clientId := range ctx.ClientIds {
		client, err := extensions.FindEnabledClientById(s.clientStore, clientId)

		if err != nil || client == nil {
			continue
		}

		if client.BackChannelLogoutUri == "" {
			continue
		}

		back := &services.BackchannelLogoutRequest{
			ClientId:          clientId,
			LogoutUri:         client.BackChannelLogoutUri,
			SubjectId:         ctx.SubjectId,
			SessionId:         ctx.SessionId,
			SessionIdRequired: client.BackChannelLogoutSessionRequired,
			Issuer:            ctx.Issuer,
		}

		backChannelLogouts = append(backChannelLogouts, back)
	}

	if len(backChannelLogouts) > 0 {
		msg := strings.Join(utils.Select(backChannelLogouts, func(x *services.BackchannelLogoutRequest) string { return x.LogoutUri }), ", ")
		s.logger.Debug("Client back-channel logout URLs", slog.String("msg", msg))
	} else {
		s.logger.Debug("No Client back-channel logout URLs")

	}

	return backChannelLogouts, nil
}
