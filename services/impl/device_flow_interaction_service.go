// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

// DeviceFlowInteractionService is the default services.DeviceFlowInteractionService.
// It reads and replaces device authorizations through the device flow code
// service; it never consults or writes stored consent.
type DeviceFlowInteractionService struct {
	codes   services.DeviceFlowCodeService
	clients storage.ClientStore
	clock   services.SystemClock
	logger  *slog.Logger
}

var _ services.DeviceFlowInteractionService = (*DeviceFlowInteractionService)(nil)

func NewDeviceFlowInteractionService(
	codes services.DeviceFlowCodeService,
	clients storage.ClientStore,
	clock services.SystemClock,
	logger *slog.Logger,
) *DeviceFlowInteractionService {
	return &DeviceFlowInteractionService{
		codes:   codes,
		clients: clients,
		clock:   clock,
		logger:  logger,
	}
}

func (s *DeviceFlowInteractionService) GetAuthorizationContext(ctx context.Context, userCode string) (*services.DeviceFlowAuthorizationContext, error) {
	record, client, err := s.pending(ctx, userCode)
	if err != nil {
		return nil, err
	}
	return &services.DeviceFlowAuthorizationContext{
		ClientId:        record.ClientId,
		ClientName:      client.ClientName,
		RequestedScopes: slices.Clone(record.RequestedScopes),
		IsOpenIdRequest: record.IsOpenId,
		Expiration:      expirationOf(record),
	}, nil
}

func (s *DeviceFlowInteractionService) Approve(ctx context.Context, userCode string, subject *claims.ClaimsPrincipal, sessionId string, scopes []string) error {
	record, _, err := s.pending(ctx, userCode)
	if err != nil {
		return err
	}

	approved := utils.Distinct(scopes)
	if subjectIdOf(subject) == "" || len(approved) == 0 {
		return services.ErrDeviceFlowInvalidApproval
	}
	for _, scope := range approved {
		if !slices.Contains(record.RequestedScopes, scope) {
			return services.ErrDeviceFlowInvalidApproval
		}
	}
	if record.IsOpenId && !slices.Contains(approved, wicket.StandardScopesOpenId) {
		return services.ErrDeviceFlowInvalidApproval
	}

	// The requested scopes are narrowed to the approved ones as well: a
	// refresh token issued for this device code is bound to them, so a
	// refresh cannot widen the grant back to the original request.
	updated := *record
	updated.IsAuthorized = true
	updated.AuthorizedScopes = slices.Clone(approved)
	updated.RequestedScopes = slices.Clone(approved)
	updated.Subject = subject
	updated.SessionId = sessionId

	if err := s.codes.UpdateByUserCode(ctx, userCode, &updated); err != nil {
		return fmt.Errorf("approve device authorization: %w", err)
	}
	s.debug("device authorization approved", slog.String("clientId", record.ClientId))
	return nil
}

func (s *DeviceFlowInteractionService) Deny(ctx context.Context, userCode string) error {
	record, _, err := s.pending(ctx, userCode)
	if err != nil {
		return err
	}

	// An authorized record without authorized scopes is what the device
	// code validator answers with access_denied.
	updated := *record
	updated.IsAuthorized = true
	updated.AuthorizedScopes = []string{}
	updated.RequestedScopes = slices.Clone(record.RequestedScopes)

	if err := s.codes.UpdateByUserCode(ctx, userCode, &updated); err != nil {
		return fmt.Errorf("deny device authorization: %w", err)
	}
	s.debug("device authorization denied", slog.String("clientId", record.ClientId))
	return nil
}

// pending loads the device authorization for userCode and its client,
// reporting an unknown, expired or already handled user code, in that order.
func (s *DeviceFlowInteractionService) pending(ctx context.Context, userCode string) (*storage_models.DeviceCode, *storage_models.Client, error) {
	record, err := s.codes.FindByUserCode(ctx, userCode)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil, services.ErrDeviceFlowUserCodeNotFound
		}
		return nil, nil, fmt.Errorf("find device authorization: %w", err)
	}
	if record == nil {
		return nil, nil, services.ErrDeviceFlowUserCodeNotFound
	}

	client, err := extensions.FindEnabledClientById(ctx, s.clients, record.ClientId)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil, services.ErrDeviceFlowUserCodeNotFound
		}
		return nil, nil, fmt.Errorf("find device authorization client: %w", err)
	}

	if expirationOf(record).Before(s.clock.Now()) {
		return nil, nil, services.ErrDeviceFlowUserCodeExpired
	}
	if record.IsAuthorized {
		return nil, nil, services.ErrDeviceFlowUserCodeAlreadyHandled
	}
	return record, client, nil
}

func (s *DeviceFlowInteractionService) debug(msg string, args ...any) {
	if s.logger != nil {
		s.logger.Debug(msg, args...)
	}
}

func expirationOf(record *storage_models.DeviceCode) time.Time {
	return record.CreationTime.Add(time.Duration(record.Lifetime) * time.Second)
}

// subjectIdOf returns the sub claim of the principal's primary identity, the
// identity token issuance reads the subject from, or "" when there is none.
func subjectIdOf(subject *claims.ClaimsPrincipal) string {
	if subject == nil {
		return ""
	}
	identity, ok := subject.Identity().(*claims.ClaimsIdentity)
	if !ok || identity == nil {
		return ""
	}
	claim := identity.FindFirst(wicket.JwtClaimTypesSubject)
	if claim == nil {
		return ""
	}
	value, _ := claim.Value.(string)
	return value
}
