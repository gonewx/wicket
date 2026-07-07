// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package storage

import "fmt"

// PersistedGrantFilter Represents a filter used when accessing the persisted grants store.
// Setting multiple properties is interpreted as a logical 'AND' to further filter the query.
// / At least one value must be supplied.
type PersistedGrantFilter struct {
	// Subject id of the user.
	SubjectId string

	// Session id used for the grant.
	SessionId string

	// Client id the grant was issued to.
	ClientId string

	// Client ids the grant was issued to.
	ClientIds []string

	// The type of grant.
	Type string

	// The types of grants.
	Types []string
}

func (f *PersistedGrantFilter) Validate() error {
	if f == nil {
		return fmt.Errorf("PersistedGrantFilter is nil")
	}

	if (f.ClientId == "" || f.ClientIds == nil) &&
		f.SessionId == "" &&
		f.SubjectId == "" &&
		(f.Type == "" || f.Types == nil) {
		return fmt.Errorf("No filter values set")
	}

	return nil
}
