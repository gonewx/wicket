// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
)

// SessionGrantRevoker removes what a browser session left behind once another
// user signs in on it: the authorization codes, refresh tokens and reference
// tokens issued within the session, and the persisted grants recorded for
// it. Grants of other sessions are not touched.
type SessionGrantRevoker struct {
	codes     storage.AuthorizationCodeStore
	refresh   storage.RefreshTokenStore
	reference storage.ReferenceTokenStore
	persisted storage.PersistedGrantStore
	logger    *slog.Logger
}

// NewSessionGrantRevoker returns a revoker over the given stores. A nil store
// is skipped.
func NewSessionGrantRevoker(
	codes storage.AuthorizationCodeStore,
	refresh storage.RefreshTokenStore,
	reference storage.ReferenceTokenStore,
	persisted storage.PersistedGrantStore,
	logger *slog.Logger,
) *SessionGrantRevoker {
	return &SessionGrantRevoker{codes: codes, refresh: refresh, reference: reference, persisted: persisted, logger: logger}
}

// Revoke removes the grants bound to sessionId from every store. Each store
// is asked once whatever the others report; the failures are joined, logged
// as one warning and returned. The removals are not cancelled with ctx.
// formerSubject is the subject the session
// belonged to and only appears in the log. An empty sessionId removes
// nothing: it would match every grant issued outside a session.
func (r *SessionGrantRevoker) Revoke(ctx context.Context, sessionId, formerSubject string) error {
	if r == nil || sessionId == "" {
		return nil
	}

	// A sign-in whose client goes away must not leave the revocation half
	// done: the removals keep the request's values but not its cancellation.
	ctx = context.WithoutCancel(ctx)

	// A count of -1 marks a store the revoker was not given.
	codes, refresh, reference := -1, -1, -1
	var errs []error
	var failures []string
	fail := func(store string, err error) {
		errs = append(errs, fmt.Errorf("%s: %w", store, err))
		failures = append(failures, fmt.Sprintf("%s (%T)", store, err))
	}
	if r.codes != nil {
		n, err := r.codes.RemoveAuthorizationCodesBySession(ctx, sessionId)
		codes = n
		if err != nil {
			fail("authorization codes", err)
		}
	}
	if r.refresh != nil {
		n, err := r.refresh.RemoveRefreshTokensBySession(ctx, sessionId)
		refresh = n
		if err != nil {
			fail("refresh tokens", err)
		}
	}
	if r.reference != nil {
		n, err := r.reference.RemoveReferenceTokensBySession(ctx, sessionId)
		reference = n
		if err != nil {
			fail("reference tokens", err)
		}
	}
	if r.persisted != nil {
		if err := r.persisted.RemoveAll(ctx, &storage.PersistedGrantFilter{SessionId: sessionId}); err != nil {
			fail("persisted grants", err)
		}
	}

	err := errors.Join(errs...)
	if r.logger == nil {
		return err
	}
	attrs := []any{
		slog.String("sessionIdPrefix", sessionIdPrefix(sessionId)),
		slog.String("formerSubject", formerSubject),
		slog.Int("authorizationCodes", codes),
		slog.Int("refreshTokens", refresh),
		slog.Int("referenceTokens", reference),
	}
	if err != nil {
		// Only the failing stores and their error types are logged: a store's
		// error text may repeat the session id it was given.
		r.logger.WarnContext(ctx, "Revoking the grants of a browser session failed",
			append(attrs, slog.String("failures", strings.Join(failures, ", ")))...)
		return err
	}
	r.logger.InfoContext(ctx, "Revoked the grants of a browser session after its subject changed", attrs...)
	return nil
}

// sessionIdPrefix is the part of a session id that may be logged.
func sessionIdPrefix(sessionId string) string {
	const n = 6
	if len(sessionId) <= n {
		return ""
	}
	return sessionId[:n]
}

// sessionSubjectChanged reports whether signing in newSubject on the session
// record changes the session's subject: the record names a subject and the
// new one is another, non-empty subject.
func sessionSubjectChanged(record *sessionpkg.Record, newSubject string) bool {
	return record != nil && record.SubjectID != "" && newSubject != "" && record.SubjectID != newSubject
}

// sessionContinues reports whether signing in newSubject at now continues the
// session of record instead of starting a new one: the record names a
// subject, it is newSubject, and the record has not expired. An expired
// record still counts for sessionSubjectChanged, but is never continued.
func sessionContinues(record *sessionpkg.Record, newSubject string, now time.Time) bool {
	return record != nil && record.SubjectID != "" && record.SubjectID == newSubject && !record.IsExpired(now)
}
