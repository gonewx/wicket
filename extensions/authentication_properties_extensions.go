// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package extensions

import (
	"encoding/base64"
	"encoding/json"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/utils"
)

const (
	SessionIdKey  = "session_id"
	ClientListKey = "client_list"
)

// GetSessionIdAuthenticationProperties Gets the user's session identifier.
func GetSessionIdAuthenticationProperties(properties *auth.Properties) string {
	if properties == nil {
		return ""
	}

	if v, ok := properties.Items[SessionIdKey]; ok {
		return v
	}

	return ""
}

// SetSessionIdAuthenticationProperties Sets the user's session identifier.
func SetSessionIdAuthenticationProperties(properties *auth.Properties, sessionId string) {
	if properties == nil {
		return
	}

	properties.Items[SessionIdKey] = sessionId
}

// GetClientListAuthenticationProperties Gets the list of client ids the user has signed into during their session.
func GetClientListAuthenticationProperties(properties *auth.Properties) ([]string, error) {
	if properties == nil {
		return nil, nil
	}

	if v, ok := properties.Items[ClientListKey]; ok {
		return DecodeList(v)
	}

	return []string{}, nil
}

// RemoveClientListAuthenticationProperties Removes the list of client ids.
func RemoveClientListAuthenticationProperties(properties *auth.Properties) {
	if properties == nil {
		return
	}

	delete(properties.Items, ClientListKey)
}

// SetClientListAuthenticationProperties Sets the list of client ids.
func SetClientListAuthenticationProperties(properties *auth.Properties, clientIds []string) {
	if properties == nil {
		return
	}

	value := EncodeList(clientIds)
	if value == "" {
		delete(properties.Items, ClientListKey)
	} else {
		properties.Items[ClientListKey] = value
	}
}

// AddClientToClientListAuthenticationProperties Adds a client to the list of clients the user has signed into during their session.
func AddClientToClientListAuthenticationProperties(properties *auth.Properties, clientId string) error {
	if properties == nil {
		return gois.ArgumentNullException
	}
	if clientId == "" {
		return gois.ArgumentNullException
	}

	clients, err := GetClientListAuthenticationProperties(properties)
	if err != nil {
		return err
	}
	if !utils.Contains(clients, clientId) {
		clients = append(clients, clientId)
		SetClientListAuthenticationProperties(properties, clients)
	}
	return nil
}

func DecodeList(value string) ([]string, error) {
	if value == "" {
		return []string{}, nil
	}

	data, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0)
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func EncodeList(list []string) string {
	if len(list) == 0 {
		return ""
	}

	data, err := json.Marshal(list)
	if err != nil {
		return ""
	}

	return base64.URLEncoding.EncodeToString(data)
}
