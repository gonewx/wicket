// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

var interactionNow = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

type fixedInteractionClock struct{ now time.Time }

func (c fixedInteractionClock) Now() time.Time { return c.now }

// fakeDeviceFlowCodes is a DeviceFlowCodeService over a map keyed by user
// code. It hands out the stored pointer, as an in-memory store does, so a
// test can see whether the caller wrote through it.
type fakeDeviceFlowCodes struct {
	records   map[string]*storage_models.DeviceCode
	findErr   error
	updateErr error
	updates   []*storage_models.DeviceCode
}

func (f *fakeDeviceFlowCodes) StoreDeviceAuthorization(ctx context.Context, userCode string, data *storage_models.DeviceCode) (string, error) {
	f.records[userCode] = data
	return "device-" + userCode, nil
}

func (f *fakeDeviceFlowCodes) FindByUserCode(ctx context.Context, userCode string) (*storage_models.DeviceCode, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	record, ok := f.records[userCode]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return record, nil
}

func (f *fakeDeviceFlowCodes) FindByDeviceCode(ctx context.Context, deviceCode string) (*storage_models.DeviceCode, error) {
	return nil, storage.ErrNotFound
}

func (f *fakeDeviceFlowCodes) UpdateByUserCode(ctx context.Context, userCode string, data *storage_models.DeviceCode) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.updates = append(f.updates, data)
	f.records[userCode] = data
	return nil
}

func (f *fakeDeviceFlowCodes) RemoveByDeviceCode(ctx context.Context, deviceCode string) error {
	return nil
}

// fakeInteractionClients is a ClientStore with a configurable failure.
type fakeInteractionClients struct {
	clients map[string]*storage_models.Client
	err     error
}

func (f *fakeInteractionClients) FindClientById(ctx context.Context, clientId string) (*storage_models.Client, error) {
	if f.err != nil {
		return nil, f.err
	}
	client, ok := f.clients[clientId]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return client, nil
}

type interactionFixture struct {
	codes   *fakeDeviceFlowCodes
	clients *fakeInteractionClients
	service *DeviceFlowInteractionService
}

func newInteractionFixture() *interactionFixture {
	client := storage_models.NewClient()
	client.ClientId = "device.client"
	client.ClientName = "Living Room TV"
	client.Enabled = true

	codes := &fakeDeviceFlowCodes{records: map[string]*storage_models.DeviceCode{
		"pending": pendingRecord(),
	}}
	clients := &fakeInteractionClients{clients: map[string]*storage_models.Client{client.ClientId: client}}
	return &interactionFixture{
		codes:   codes,
		clients: clients,
		service: NewDeviceFlowInteractionService(codes, clients, fixedInteractionClock{now: interactionNow}, slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
}

func pendingRecord() *storage_models.DeviceCode {
	return &storage_models.DeviceCode{
		ClientId:        "device.client",
		CreationTime:    interactionNow.Add(-time.Minute),
		Lifetime:        300,
		IsOpenId:        true,
		RequestedScopes: []string{"openid", "profile", "api1", "offline_access"},
	}
}

func subjectPrincipal(sub any) *claims.ClaimsPrincipal {
	return claims.NewClaimsPrincipal(claims.WithClaimsPrincipalIdentity(claims.NewClaimsIdentity(
		claims.WithAuthenticationType("pwd"),
		claims.WithClaims([]*claims.Claim{claims.NewClaim(claims.WithClaimType(wicket.JwtClaimTypesSubject), claims.WithClaimValue(sub))}),
	)))
}

// Each operation shares one sequence of checks: store failure, unknown user
// code, expiry, already handled. The first that applies is reported.
func TestDeviceFlowInteractionPrecondition(t *testing.T) {
	storeFailure := errors.New("store unavailable")

	cases := map[string]struct {
		userCode string
		arrange  func(f *interactionFixture)
		want     error
		wrapped  bool
	}{
		"store failure is returned wrapped": {
			userCode: "pending",
			arrange:  func(f *interactionFixture) { f.codes.findErr = storeFailure },
			want:     storeFailure,
			wrapped:  true,
		},
		"unknown user code": {
			userCode: "missing",
			want:     services.ErrDeviceFlowUserCodeNotFound,
		},
		"client no longer exists": {
			userCode: "pending",
			arrange:  func(f *interactionFixture) { delete(f.clients.clients, "device.client") },
			want:     services.ErrDeviceFlowUserCodeNotFound,
		},
		"client disabled": {
			userCode: "pending",
			arrange:  func(f *interactionFixture) { f.clients.clients["device.client"].Enabled = false },
			want:     services.ErrDeviceFlowUserCodeNotFound,
		},
		"client store failure is returned wrapped": {
			userCode: "pending",
			arrange:  func(f *interactionFixture) { f.clients.err = storeFailure },
			want:     storeFailure,
			wrapped:  true,
		},
		"expired": {
			userCode: "pending",
			arrange: func(f *interactionFixture) {
				f.codes.records["pending"].CreationTime = interactionNow.Add(-301 * time.Second)
			},
			want: services.ErrDeviceFlowUserCodeExpired,
		},
		"already approved": {
			userCode: "pending",
			arrange: func(f *interactionFixture) {
				record := f.codes.records["pending"]
				record.IsAuthorized = true
				record.AuthorizedScopes = []string{"openid"}
			},
			want: services.ErrDeviceFlowUserCodeAlreadyHandled,
		},
		"already denied": {
			userCode: "pending",
			arrange:  func(f *interactionFixture) { f.codes.records["pending"].IsAuthorized = true },
			want:     services.ErrDeviceFlowUserCodeAlreadyHandled,
		},
		"handled and expired reports expiry": {
			userCode: "pending",
			arrange: func(f *interactionFixture) {
				record := f.codes.records["pending"]
				record.IsAuthorized = true
				record.CreationTime = interactionNow.Add(-time.Hour)
			},
			want: services.ErrDeviceFlowUserCodeExpired,
		},
		"missing client of an expired record reports not found": {
			userCode: "pending",
			arrange: func(f *interactionFixture) {
				f.codes.records["pending"].CreationTime = interactionNow.Add(-time.Hour)
				delete(f.clients.clients, "device.client")
			},
			want: services.ErrDeviceFlowUserCodeNotFound,
		},
	}

	operations := map[string]func(f *interactionFixture, userCode string) error{
		"GetAuthorizationContext": func(f *interactionFixture, userCode string) error {
			got, err := f.service.GetAuthorizationContext(context.Background(), userCode)
			if err != nil && got != nil {
				t.Fatalf("context %v returned together with error %v", got, err)
			}
			return err
		},
		"Approve": func(f *interactionFixture, userCode string) error {
			// The approval itself is invalid, so a precondition must win.
			return f.service.Approve(context.Background(), userCode, nil, "", nil)
		},
		"Deny": func(f *interactionFixture, userCode string) error {
			return f.service.Deny(context.Background(), userCode)
		},
	}

	for name, tc := range cases {
		for operation, run := range operations {
			t.Run(name+"/"+operation, func(t *testing.T) {
				f := newInteractionFixture()
				if tc.arrange != nil {
					tc.arrange(f)
				}

				err := run(f, tc.userCode)

				if !errors.Is(err, tc.want) {
					t.Fatalf("error = %v, want %v", err, tc.want)
				}
				if tc.wrapped && err == tc.want {
					t.Fatalf("error %v returned without context", err)
				}
				if len(f.codes.updates) != 0 {
					t.Fatalf("record written despite error: %v", f.codes.updates)
				}
			})
		}
	}
}

func TestDeviceFlowInteractionGetAuthorizationContext(t *testing.T) {
	f := newInteractionFixture()

	got, err := f.service.GetAuthorizationContext(context.Background(), "pending")
	if err != nil {
		t.Fatalf("GetAuthorizationContext: %v", err)
	}
	if got.ClientId != "device.client" || got.ClientName != "Living Room TV" {
		t.Fatalf("client = %q / %q", got.ClientId, got.ClientName)
	}
	if !got.IsOpenIdRequest {
		t.Fatal("IsOpenIdRequest = false, want true")
	}
	if !slices.Equal(got.RequestedScopes, []string{"openid", "profile", "api1", "offline_access"}) {
		t.Fatalf("RequestedScopes = %v", got.RequestedScopes)
	}
	if want := interactionNow.Add(4 * time.Minute); !got.Expiration.Equal(want) {
		t.Fatalf("Expiration = %v, want %v", got.Expiration, want)
	}

	got.RequestedScopes[0] = "changed"
	if f.codes.records["pending"].RequestedScopes[0] != "openid" {
		t.Fatal("context shares its scopes with the stored record")
	}
}

func TestDeviceFlowInteractionApproveRejectsInvalidApproval(t *testing.T) {
	valid := subjectPrincipal("alice")
	nilIdentity := &claims.ClaimsPrincipal{Identities: []*claims.ClaimsIdentity{nil}}

	cases := map[string]struct {
		subject *claims.ClaimsPrincipal
		scopes  []string
		openId  bool
	}{
		"nil subject":                       {subject: nil, scopes: []string{"openid"}, openId: true},
		"subject without identities":        {subject: claims.NewClaimsPrincipal(), scopes: []string{"openid"}, openId: true},
		"subject with a nil identity":       {subject: nilIdentity, scopes: []string{"openid"}, openId: true},
		"subject without sub":               {subject: claims.NewClaimsPrincipal(claims.WithClaimsPrincipalIdentity(claims.NewClaimsIdentity())), scopes: []string{"openid"}, openId: true},
		"subject with an empty sub":         {subject: subjectPrincipal(""), scopes: []string{"openid"}, openId: true},
		"subject with a non-string sub":     {subject: subjectPrincipal(42), scopes: []string{"openid"}, openId: true},
		"no scopes":                         {subject: valid, scopes: nil, openId: true},
		"empty scope list":                  {subject: valid, scopes: []string{}, openId: true},
		"scope that was not requested":      {subject: valid, scopes: []string{"openid", "email"}, openId: true},
		"OpenID request without openid":     {subject: valid, scopes: []string{"api1"}, openId: true},
		"empty scope value":                 {subject: valid, scopes: []string{"openid", ""}, openId: true},
		"non-OpenID request widening scope": {subject: valid, scopes: []string{"api2"}, openId: false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newInteractionFixture()
			f.codes.records["pending"].IsOpenId = tc.openId

			err := f.service.Approve(context.Background(), "pending", tc.subject, "session", tc.scopes)

			if !errors.Is(err, services.ErrDeviceFlowInvalidApproval) {
				t.Fatalf("error = %v, want ErrDeviceFlowInvalidApproval", err)
			}
			if len(f.codes.updates) != 0 {
				t.Fatalf("record written for an invalid approval: %v", f.codes.updates)
			}
		})
	}
}

func TestDeviceFlowInteractionApproveWritesNarrowedCopy(t *testing.T) {
	f := newInteractionFixture()
	original := f.codes.records["pending"]
	originalRequested := original.RequestedScopes
	subject := subjectPrincipal("alice")
	scopes := []string{"openid", "api1", "openid"}

	if err := f.service.Approve(context.Background(), "pending", subject, "session-1", scopes); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	if len(f.codes.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(f.codes.updates))
	}
	written := f.codes.updates[0]
	if written == original {
		t.Fatal("the stored record was updated in place instead of replaced by a copy")
	}
	if !written.IsAuthorized || written.Subject != subject || written.SessionId != "session-1" {
		t.Fatalf("written record = %+v", written)
	}
	if !slices.Equal(written.AuthorizedScopes, []string{"openid", "api1"}) {
		t.Fatalf("AuthorizedScopes = %v, want [openid api1]", written.AuthorizedScopes)
	}
	if !slices.Equal(written.RequestedScopes, []string{"openid", "api1"}) {
		t.Fatalf("RequestedScopes = %v, want the approved subset [openid api1]", written.RequestedScopes)
	}
	if written.ClientId != original.ClientId || !written.CreationTime.Equal(original.CreationTime) || written.Lifetime != original.Lifetime || !written.IsOpenId {
		t.Fatalf("copied fields changed: %+v", written)
	}

	// The record handed out by the store is left as it was.
	if original.IsAuthorized || original.Subject != nil || original.SessionId != "" || original.AuthorizedScopes != nil {
		t.Fatalf("stored record modified in place: %+v", original)
	}
	if !slices.Equal(originalRequested, []string{"openid", "profile", "api1", "offline_access"}) {
		t.Fatalf("original requested scopes modified: %v", originalRequested)
	}

	// The written slices are not shared with the caller's argument or with
	// each other.
	scopes[1] = "changed"
	written.AuthorizedScopes[0] = "changed"
	if written.RequestedScopes[0] != "openid" || written.AuthorizedScopes[1] != "api1" {
		t.Fatalf("written slices share storage: authorized=%v requested=%v", written.AuthorizedScopes, written.RequestedScopes)
	}
}

func TestDeviceFlowInteractionApproveAllowsEmptySessionAndNonOpenIdRequest(t *testing.T) {
	f := newInteractionFixture()
	f.codes.records["pending"].IsOpenId = false
	f.codes.records["pending"].RequestedScopes = []string{"api1", "api2"}

	if err := f.service.Approve(context.Background(), "pending", subjectPrincipal("alice"), "", []string{"api2"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if written := f.codes.updates[0]; !slices.Equal(written.AuthorizedScopes, []string{"api2"}) || written.SessionId != "" {
		t.Fatalf("written record = %+v", written)
	}
}

func TestDeviceFlowInteractionDenyWritesDenialCopy(t *testing.T) {
	f := newInteractionFixture()
	original := f.codes.records["pending"]

	if err := f.service.Deny(context.Background(), "pending"); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	if len(f.codes.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(f.codes.updates))
	}
	written := f.codes.updates[0]
	if written == original {
		t.Fatal("the stored record was updated in place instead of replaced by a copy")
	}
	if !written.IsAuthorized || len(written.AuthorizedScopes) != 0 || written.Subject != nil {
		t.Fatalf("written record = %+v, want authorized with no scopes and no subject", written)
	}
	if original.IsAuthorized {
		t.Fatal("stored record modified in place")
	}

	// A second decision on the same user code is refused.
	if err := f.service.Approve(context.Background(), "pending", subjectPrincipal("alice"), "", []string{"openid"}); !errors.Is(err, services.ErrDeviceFlowUserCodeAlreadyHandled) {
		t.Fatalf("Approve after Deny = %v, want ErrDeviceFlowUserCodeAlreadyHandled", err)
	}
}

// A failed write is returned wrapped and never mapped to a sentinel, even
// when the store reports the record missing.
func TestDeviceFlowInteractionUpdateFailureIsWrapped(t *testing.T) {
	for _, updateErr := range []error{errors.New("store unavailable"), storage.ErrNotFound} {
		for operation, run := range map[string]func(f *interactionFixture) error{
			"Approve": func(f *interactionFixture) error {
				return f.service.Approve(context.Background(), "pending", subjectPrincipal("alice"), "", []string{"openid"})
			},
			"Deny": func(f *interactionFixture) error {
				return f.service.Deny(context.Background(), "pending")
			},
		} {
			t.Run(operation+"/"+updateErr.Error(), func(t *testing.T) {
				f := newInteractionFixture()
				f.codes.updateErr = updateErr

				err := run(f)

				if !errors.Is(err, updateErr) || err == updateErr {
					t.Fatalf("error = %v, want %v wrapped", err, updateErr)
				}
				for _, sentinel := range []error{
					services.ErrDeviceFlowUserCodeNotFound,
					services.ErrDeviceFlowUserCodeExpired,
					services.ErrDeviceFlowUserCodeAlreadyHandled,
					services.ErrDeviceFlowInvalidApproval,
				} {
					if errors.Is(err, sentinel) {
						t.Fatalf("error %v mapped to %v", err, sentinel)
					}
				}
			})
		}
	}
}
