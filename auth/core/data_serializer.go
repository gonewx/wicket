// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

type DataSerializer[T any] interface {
	Serialize(model *T) []byte
	Deserialize(data []byte) *T
}
