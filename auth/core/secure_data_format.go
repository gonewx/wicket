// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/gonewx/wicket/dp"
)

// SecureDataFormat A contract for securing data.
type SecureDataFormat[T any] interface {
	// Protects the specified <paramref name="data"/>.
	Protect(data *T) string
	// Protects the specified data for the specified purpose.
	ProtectWithPurpose(data *T, purpose string) string
	// Unprotects the specified protectedText.
	Unprotect(protectedText string) *T
	// Unprotects the specified protectedText> using the specified purpose.
	UnprotectWithPurpose(protectedText string, purpose string) *T
}

type secureDataFormat[T any] struct {
	serializer DataSerializer[T]
	protector  dp.DataProtector
}

func NewSecureDataFormat[T any](
	serializer DataSerializer[T],
	protector dp.DataProtector,
) SecureDataFormat[T] {
	return &secureDataFormat[T]{
		serializer: serializer,
		protector:  protector,
	}
}

func (f *secureDataFormat[T]) Protect(data *T) string {
	return f.ProtectWithPurpose(data, "")
}

func (f *secureDataFormat[T]) ProtectWithPurpose(data *T, purpose string) string {
	// TODO: just support json serializer for now
	// userData := f.serializer.Serialize(data)
	userData, err := json.Marshal(data)
	if err != nil {
		// TODO: return error
		panic(err)
	}

	protector := f.protector
	if strings.TrimSpace(purpose) != "" {
		protector = protector.Create(purpose)
	}

	protectedData := protector.Protect(userData)

	return base64.StdEncoding.EncodeToString(protectedData)
}

func (f *secureDataFormat[T]) Unprotect(protectedText string) *T {
	return f.UnprotectWithPurpose(protectedText, "")
}

func (f *secureDataFormat[T]) UnprotectWithPurpose(protectedText string, purpose string) *T {
	var zero *T
	if strings.TrimSpace(protectedText) == "" {
		return zero
	}

	protectedData, err := base64.StdEncoding.DecodeString(protectedText)
	if err != nil {
		return zero
	}

	protector := f.protector
	if strings.TrimSpace(purpose) != "" {
		protector = protector.Create(purpose)
	}

	userData, err := protector.Unprotect(protectedData)

	if err != nil || userData == nil {
		return zero
	}
	// TODO: just support json serializer for now
	// return f.serializer.Deserialize(userData)
	var data T
	err = json.Unmarshal(userData, &data)
	if err != nil {
		return &data
	}
	return &data
}
