// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"log/slog"
	"os"
)

func NewTestLogger() *slog.Logger {
	opts := slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &opts))
}
