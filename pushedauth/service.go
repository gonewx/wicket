// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package pushedauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

var (
	// ErrRequestUriInvalid reports a request_uri that cannot be used: it is
	// unknown, bound to another client, expired, or its payload cannot be
	// read. The authorize endpoint answers it with invalid_request_uri.
	ErrRequestUriInvalid = errors.New("pushedauth: invalid request_uri")
	// ErrClientRejected reports that the client of a pushed request is
	// absent, disabled or invalidly configured when the request is consumed.
	ErrClientRejected = errors.New("pushedauth: client rejected")
	// ErrRequestUriConsumed reports that the pushed request was already
	// consumed, by an earlier response or a concurrent one.
	ErrRequestUriConsumed = errors.New("pushedauth: request_uri already consumed")
)

// Service stores, resolves and consumes pushed authorization requests. Every
// store key comes from storage.PushedAuthorizationRequestKey, and every
// payload and entry receipt is protected by the pushed authorization
// protector.
type Service struct {
	store     storage.PushedAuthorizationRequestStore
	protector dp.DataProtector
	clients   storage.ClientStore
	options   Options
}

// NewService builds the service. options must carry a clock and no negative
// duration; zero durations take their defaults.
func NewService(store storage.PushedAuthorizationRequestStore, protector dp.DataProtector, clients storage.ClientStore, options Options) (*Service, error) {
	if store == nil {
		return nil, errors.New("pushedauth: no pushed authorization request store")
	}
	if protector == nil {
		return nil, errors.New("pushedauth: no data protector")
	}
	if clients == nil {
		return nil, errors.New("pushedauth: no client store")
	}
	if options.Clock == nil {
		return nil, errors.New("pushedauth: no clock")
	}
	if err := options.Validate(); err != nil {
		return nil, err
	}
	return &Service{store: store, protector: protector, clients: clients, options: options.WithDefaults()}, nil
}

// Options returns the effective options, defaults applied.
func (s *Service) Options() Options {
	return s.options
}

// Required reports whether client may use the authorize endpoint only
// through a pushed request_uri.
func (s *Service) Required(client *storage_models.Client) bool {
	return s.options.RequireForAllClients || (client != nil && client.RequirePushedAuthorizationRequests)
}

// EntryLifetime returns the entry lifetime of the request_uri handles issued
// to client: its own RequestUriLifetime when positive, the configured one
// otherwise.
func (s *Service) EntryLifetime(client *storage_models.Client) time.Duration {
	if client != nil && client.RequestUriLifetime > 0 {
		return time.Duration(client.RequestUriLifetime) * time.Second
	}
	return s.options.RequestUriLifetime
}

// Push stores parameters as a pushed authorization request of client and
// returns the request_uri handed to the client together with its entry
// lifetime in seconds. parameters must carry the client's client_id.
func (s *Service) Push(ctx context.Context, client *storage_models.Client, parameters url.Values) (string, int, error) {
	if client == nil {
		return "", 0, errors.New("pushedauth: push without a client")
	}
	requestURI, err := storage.NewPushedAuthorizationRequestURI()
	if err != nil {
		return "", 0, fmt.Errorf("pushedauth: push: %w", err)
	}
	key, err := storage.PushedAuthorizationRequestKey(requestURI)
	if err != nil {
		return "", 0, fmt.Errorf("pushedauth: push: %w", err)
	}
	payload, err := storage.ProtectPushedAuthorizationParameters(s.protector, parameters)
	if err != nil {
		return "", 0, fmt.Errorf("pushedauth: push: %w", err)
	}
	lifetime := s.EntryLifetime(client)
	now := s.options.Clock.Now()
	entryExpiration := now.Add(lifetime)
	record := &storage_models.PushedAuthorizationRequest{
		ClientId:            client.ClientId,
		CreationTime:        now,
		EntryExpiration:     entryExpiration,
		RetentionExpiration: entryExpiration.Add(s.options.InteractionGracePeriod),
		Payload:             payload,
	}
	if err := s.store.StorePushedAuthorizationRequest(ctx, key, record); err != nil {
		return "", 0, fmt.Errorf("pushedauth: store pushed authorization request: %w", err)
	}
	return requestURI, int(lifetime / time.Second), nil
}

// Resolve reads, without consuming it, the pushed request requestURI names
// for the client clientId and returns its parameters together with the entry
// receipt the request carries from now on.
//
// interactionReturn says the caller declared an interaction round trip. The
// request is judged as a round trip, against its retention expiration, only
// when receipt is a valid entry receipt of this request_uri; otherwise it is
// judged as an entry, against its entry expiration, and a fresh receipt is
// issued. Every reason the request_uri cannot be used returns an error
// matching ErrRequestUriInvalid; any other error is a store failure.
func (s *Service) Resolve(ctx context.Context, requestURI string, clientId string, receipt string, interactionReturn bool) (url.Values, string, error) {
	key, err := storage.PushedAuthorizationRequestKey(requestURI)
	if err != nil {
		return nil, "", ErrRequestUriInvalid
	}
	record, err := s.store.GetPushedAuthorizationRequest(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, "", ErrRequestUriInvalid
		}
		return nil, "", fmt.Errorf("pushedauth: read pushed authorization request: %w", err)
	}
	if record == nil || clientId == "" || record.ClientId != clientId {
		return nil, "", ErrRequestUriInvalid
	}
	now := s.options.Clock.Now()
	roundTrip := interactionReturn && validEntryReceipt(s.protector, receipt, key, now, record.EntryExpiration)
	deadline := record.EntryExpiration
	if roundTrip {
		deadline = record.RetentionExpiration
	}
	if !now.Before(deadline) {
		return nil, "", ErrRequestUriInvalid
	}
	parameters, err := storage.UnprotectPushedAuthorizationParameters(s.protector, record.Payload)
	if err != nil {
		return nil, "", ErrRequestUriInvalid
	}
	if ids := parameters[wicket.AuthorizeRequestClientId]; len(ids) != 1 || ids[0] != record.ClientId {
		return nil, "", ErrRequestUriInvalid
	}
	if roundTrip {
		return parameters, receipt, nil
	}
	issued, err := issueEntryReceipt(s.protector, key, now)
	if err != nil {
		return nil, "", fmt.Errorf("pushedauth: issue entry receipt: %w", err)
	}
	return parameters, issued, nil
}

// Consume atomically takes the pushed request requestURI names, once the
// authorize endpoint answers the client clientId. The client is reloaded
// first: an absent, disabled or invalidly configured client returns an error
// matching ErrClientRejected and leaves the request in place. A request
// already taken returns an error matching ErrRequestUriConsumed. Any other
// error is an infrastructure failure.
func (s *Service) Consume(ctx context.Context, requestURI string, clientId string) error {
	if _, err := extensions.FindEnabledClientById(ctx, s.clients, clientId); err != nil {
		if extensions.IsClientRejected(err) {
			return fmt.Errorf("%w: %w", ErrClientRejected, err)
		}
		return fmt.Errorf("pushedauth: reload client: %w", err)
	}
	key, err := storage.PushedAuthorizationRequestKey(requestURI)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRequestUriConsumed, err)
	}
	record, err := s.store.TakePushedAuthorizationRequest(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%w: %w", ErrRequestUriConsumed, err)
		}
		return fmt.Errorf("pushedauth: take pushed authorization request: %w", err)
	}
	if record == nil || record.ClientId != clientId {
		return ErrClientRejected
	}
	return nil
}
