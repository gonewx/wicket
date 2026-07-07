// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"encoding/json"
	"fmt"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dp"
)

func WithPersistentGrantOptions(options *config_options.PersistentGrantOptions) gois.Option[PersistentGrantSerializer] {
	return func(s *PersistentGrantSerializer) {
		s.options = options
	}
}

func WithPersistentGrantDataProtector(dataProtector dp.DataProtectionProvider) gois.Option[PersistentGrantSerializer] {
	return func(s *PersistentGrantSerializer) {
		s.protector = dataProtector.Create("PersistentGrantSerializer")
	}
}

// PersistentGrantSerializer JSON-based persisted grant serializer
// From: IdentityServer4/src/Storage/Stores/Serialization/PersistentGrantSerializer.cs
//
// NFR3/FR27 deviation: dotnet exposes a non-generic IPersistentGrantSerializer
// with generic Serialize<T>/Deserialize<T> methods. Go interfaces cannot declare
// generic methods, so gois injects this concrete type directly.
type PersistentGrantSerializer struct {
	options   *config_options.PersistentGrantOptions
	protector dp.DataProtector
}

func NewPersistentGrantSerializer(opts ...gois.Option[PersistentGrantSerializer]) *PersistentGrantSerializer {
	s := &PersistentGrantSerializer{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Serializes the specified value.
// From: IdentityServer4/src/Storage/Stores/Serialization/PersistentGrantSerializer.cs
func (s *PersistentGrantSerializer) Serialize[T any](value *T) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	if s.ShouldDataProtect() {
		payload = s.protector.Protect(payload)
	}

	data := &PersistentGrantDataContainer{
		PersistentGrantDataContainerVersion: 1,
		DataProtected:                       s.ShouldDataProtect(),
		Payload:                             payload,
	}

	return json.Marshal(data)
}

// Deserializes the specified string.
// From: IdentityServer4/src/Storage/Stores/Serialization/PersistentGrantSerializer.cs
func (s *PersistentGrantSerializer) Deserialize[T any](value []byte) (*T, error) {
	container := &PersistentGrantDataContainer{}

	err := json.Unmarshal(value, container)
	if err != nil {
		return nil, err
	}
	var data T
	if container.PersistentGrantDataContainerVersion == 0 {
		err = json.Unmarshal([]byte(value), &data)
		if err != nil {
			return nil, err
		}
		return &data, nil
	}

	if container.PersistentGrantDataContainerVersion != 1 {
		return nil, fmt.Errorf("Invalid version in persisted grant data : %d", container.PersistentGrantDataContainerVersion)
	}

	payload := container.Payload

	if container.DataProtected {
		if s.protector == nil {
			return nil, fmt.Errorf("No IDataProtectionProvider configured")
		}

		payload, err = s.protector.Unprotect(payload)
		if err != nil {
			return nil, err
		}
	}

	err = json.Unmarshal(payload, &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func (s *PersistentGrantSerializer) ShouldDataProtect() bool {
	if s.options != nil && s.options.DataProtectData && s.protector != nil {
		return true
	}
	return false
}

type PersistentGrantDataContainer struct {
	PersistentGrantDataContainerVersion int
	DataProtected                       bool
	Payload                             []byte
}
