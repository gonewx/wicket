// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package di

import (
	"log/slog"

	"github.com/gonewx/godi"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dp"
	"github.com/gonewx/wicket/infrastructure"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
)

func AddMessageCookie[T any](r *godi.Registry) *godi.Registry {
	return godi.AddTransientFactory[*infrastructure.MessageCookie[T]](r, func(p godi.Provider) *infrastructure.MessageCookie[T] {
		return infrastructure.NewMessageCookie[T](
			godi.GetRequired[*slog.Logger](p),
			godi.GetRequired[*config_options.IdentityServerOptions](p),
			requestFromProvider(p),
			responseFromProvider(p),
			godi.GetRequired[services.ServerUrls](p),
			godi.GetRequired[dp.DataProtectionProvider](p),
		)
	})
}

func AddProtectedMessageStore[T any](r *godi.Registry) *godi.Registry {
	return godi.AddTransientFactory[storage.MessageStore[T]](r, func(p godi.Provider) storage.MessageStore[T] {
		return storage_impl.NewProtectedDataMessageStore[T](
			godi.GetRequired[dp.DataProtectionProvider](p),
			godi.GetRequired[*slog.Logger](p),
		)
	})
}

func AddPersistentGrantSerializer(r *godi.Registry) *godi.Registry {
	// From: BuilderExtensions/Core.cs#L206 TryAddTransient<IPersistentGrantSerializer, PersistentGrantSerializer>.
	// Keep the current Go wire format by using the existing bare constructor;
	// injecting PersistentGrantOptions/DataProtectionProvider would enable
	// data protection and change persisted grant payloads.
	return godi.AddTransientFactory[*storage_impl.PersistentGrantSerializer](r, func(p godi.Provider) *storage_impl.PersistentGrantSerializer {
		return storage_impl.NewPersistentGrantSerializer()
	})
}
