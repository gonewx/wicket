// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/session"
)

type SessionCoordinationAdapter struct {
	coordinator *session.Coordinator
}

func NewSessionCoordinationAdapter(coordinator *session.Coordinator) *SessionCoordinationAdapter {
	return &SessionCoordinationAdapter{coordinator: coordinator}
}

func (a *SessionCoordinationAdapter) ValidateSession(req *services.SessionValidationRequest) (bool, error) {
	if a.coordinator == nil {
		return true, nil
	}
	sessionID := ""
	if req != nil {
		sessionID = req.SessionId
	}
	return a.coordinator.ValidateSession(sessionID)
}
