// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// errConfirmationNotAnObject reports a confirmation that is not a JSON
// object and so cannot be merged.
var errConfirmationNotAnObject = errors.New("access token confirmation is not a JSON object")

// CombineAccessTokenConfirmations returns a confirmation that consults both
// first and second. When either is nil the other is returned as it is. The
// combined confirmation returns the result of one side unchanged when the
// other yields "", and the members of both merged into one JSON object when
// both yield a value. Either side failing, either value not being a JSON
// object, or both naming the same member yields an error, which refuses
// issuing the token.
func CombineAccessTokenConfirmations(first, second AccessTokenConfirmation) AccessTokenConfirmation {
	if first == nil {
		return second
	}
	if second == nil {
		return first
	}
	return combinedAccessTokenConfirmation{first: first, second: second}
}

type combinedAccessTokenConfirmation struct {
	first, second AccessTokenConfirmation
}

func (c combinedAccessTokenConfirmation) Confirmation(ctx context.Context, request *http.Request, clientId string) (string, error) {
	first, err := c.first.Confirmation(ctx, request, clientId)
	if err != nil {
		return "", err
	}
	second, err := c.second.Confirmation(ctx, request, clientId)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(second) == "" {
		return first, nil
	}
	if strings.TrimSpace(first) == "" {
		return second, nil
	}
	merged, err := confirmationMembers(first)
	if err != nil {
		return "", err
	}
	others, err := confirmationMembers(second)
	if err != nil {
		return "", err
	}
	for name, value := range others {
		if _, taken := merged[name]; taken {
			return "", fmt.Errorf("access token confirmations both name member %q", name)
		}
		merged[name] = value
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		return "", fmt.Errorf("encode access token confirmation: %w", err)
	}
	return string(encoded), nil
}

func confirmationMembers(confirmation string) (map[string]json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal([]byte(confirmation), &members); err != nil || members == nil {
		return nil, errConfirmationNotAnObject
	}
	return members, nil
}
