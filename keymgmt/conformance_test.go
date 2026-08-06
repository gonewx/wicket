// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmt_test

import (
	"testing"

	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/keymgmt/keymgmttest"
)

// TestMemoryRecordStoreConformanceE2E wires the in-repo memory store into
// the keymgmt conformance suite, MUST and MAY alike. The suite is the
// executable definition of the keymgmt.RecordStore port; the store must
// satisfy every case.
func TestMemoryRecordStoreConformanceE2E(t *testing.T) {
	t.Parallel()
	keymgmttest.RunRecordStoreSuite(t, func() keymgmt.RecordStore {
		return keymgmt.NewMemoryRecordStore()
	}, keymgmttest.WithMay(true))
}
