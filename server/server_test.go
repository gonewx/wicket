// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package server

import (
	"io"
	"log/slog"
	"testing"

	"github.com/gonewx/godi"
	"github.com/stretchr/testify/require"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestServerTestService(t *testing.T) {
	t.Parallel()

	sentinel := struct{ name string }{name: "present"}

	cases := map[string]struct {
		resolve     serviceResolver
		message     string
		doThrow     bool
		wantPanic   bool
		wantPanicAs string
		wantReturn  any
	}{
		"panics with the provided message when a required service is missing": {
			resolve:     func(godi.Provider) any { return nil },
			message:     "missing service",
			doThrow:     true,
			wantPanic:   true,
			wantPanicAs: "missing service",
		},
		"panics with the default message when the message is empty": {
			resolve:     func(godi.Provider) any { return nil },
			message:     "",
			doThrow:     true,
			wantPanic:   true,
			wantPanicAs: "Required service is not registered. Aborting startup",
		},
		"returns nil without panic when throwing is disabled": {
			resolve:    func(godi.Provider) any { return nil },
			message:    "missing service",
			doThrow:    false,
			wantReturn: nil,
		},
		"returns the resolved service unchanged when present": {
			resolve:    func(godi.Provider) any { return sentinel },
			message:    "missing service",
			doThrow:    true,
			wantReturn: sentinel,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := &Server{Logger: discardLogger()}

			if tc.wantPanic {
				require.PanicsWithValue(t, tc.wantPanicAs, func() {
					s.TestService(nil, tc.resolve, discardLogger(), tc.message, tc.doThrow)
				})
				return
			}

			got := s.TestService(nil, tc.resolve, discardLogger(), tc.message, tc.doThrow)
			require.Equal(t, tc.wantReturn, got)
		})
	}
}
