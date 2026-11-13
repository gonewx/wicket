// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package infrastructure

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gonewx/wicket"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dp"
	models_messages "github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/utils"
)

type MessageCookie[T any] struct {
	logger    *slog.Logger
	options   *config_options.WicketOptions
	request   *http.Request
	response  http.ResponseWriter
	urls      services.ServerUrls
	protector dp.DataProtector

	messageType  string
	cookiePrefix string
}

func NewMessageCookie[T any](
	logger *slog.Logger,
	options *config_options.WicketOptions,
	request *http.Request,
	response http.ResponseWriter,
	urls services.ServerUrls,
	provider dp.DataProtectionProvider,
) *MessageCookie[T] {
	var t T
	// Cookie names include this exact type string; %T preserves named-type output.
	messageType := fmt.Sprintf("%T", t)
	cookiePrefix := messageType + "."
	return &MessageCookie[T]{
		logger:       logger,
		options:      options,
		request:      request,
		response:     response,
		urls:         urls,
		messageType:  messageType,
		cookiePrefix: cookiePrefix,
		protector:    provider.Create(messageType),
	}
}

func (m *MessageCookie[T]) protect(message *models_messages.Message[T]) ([]byte, error) {
	b, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}

	return m.protector.Protect(b), nil
}

func (m *MessageCookie[T]) unprotect(data []byte) (*models_messages.Message[T], error) {
	b, err := m.protector.Unprotect(data)
	if err != nil {
		return nil, err
	}

	message := models_messages.Message[T]{}
	err = json.Unmarshal(b, &message)
	if err != nil {
		return nil, err
	}

	return &message, nil
}

func (m *MessageCookie[T]) cookieFullName(id string) string {
	return m.cookiePrefix + id
}

func (m *MessageCookie[T]) cookiePath() string {
	return utils.CleanUrlPath(m.urls.BasePath())
}

func (m *MessageCookie[T]) cookieNames() []string {
	key := m.cookiePrefix
	names := make([]string, 0)
	for _, cookie := range m.request.Cookies() {
		if strings.HasPrefix(cookie.Name, key) {
			return append(names, cookie.Name)
		}
	}

	return names
}

func (m *MessageCookie[T]) secure() bool {
	return m.request.TLS != nil
}

func (m *MessageCookie[T]) readByCookieName(name string) *models_messages.Message[T] {
	cookie, err := m.request.Cookie(name)
	if err != nil {
		if err != http.ErrNoCookie {
			m.logger.Error("Error get cookie from request", "err", err)
		}
		return nil
	}

	data, err := m.unprotect([]byte(cookie.Value))

	if err != nil {
		m.logger.Error("Error unprotecting message cookie", "err", err)
		m.clearByCookieName(name)
	}
	return data
}

func (m *MessageCookie[T]) Clear(id string) {
	name := m.cookieFullName(id)
	m.clearByCookieName(name)
}

func (m *MessageCookie[T]) clearByCookieName(name string) {
	c := http.Cookie{
		Name:     name,
		Value:    ".",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   m.secure(),
		Path:     m.cookiePath(),
	}

	w := m.response

	http.SetCookie(w, &c)
}

func (m *MessageCookie[T]) cookieRank(name string) (rank int64) {
	// empty and invalid cookies are considered to be the oldest:
	message := m.readByCookieName(name)
	if message == nil {
		return
	}

	// valid cookies are ranked based on their creation time:
	return message.Created
}

func (m *MessageCookie[T]) clearOverflow() {
	names := m.cookieNames()
	toKeep := m.options.UserInteraction.CookieMessageThreshold

	if len(names) < toKeep {
		return
	}
	rankedCookieNames := utils.OrderByKeyDescMust(names, func(n string) int64 {
		rank := m.cookieRank(n)
		return rank
	})

	if toKeep-1 < 0 {
		toKeep = 0
	}

	purge := utils.Skip(rankedCookieNames, toKeep)
	for _, name := range purge {
		m.logger.Debug("Purging stale cookie:", slog.String("cookieName", name))
		m.clearByCookieName(name)
	}
}

func (m *MessageCookie[T]) Write(id string, message *models_messages.Message[T]) error {
	m.clearOverflow()

	if message == nil {
		return wicket.ArgumentNullException
	}

	name := m.cookieFullName(id)
	data, err := m.protect(message)
	if err != nil {
		return err
	}

	c := http.Cookie{
		Name:     name,
		Value:    string(data),
		HttpOnly: true,
		Secure:   m.secure(),
		Path:     m.cookiePath(),
		// IsEssential: true,
		// don't need to set same-site since cookie is expected to be sent
		// to only another page in this host.
	}

	w := m.response

	http.SetCookie(w, &c)

	return nil
}

func (m *MessageCookie[T]) Read(id string) *models_messages.Message[T] {
	if id == "" {
		return nil
	}

	name := m.cookieFullName(id)

	return m.readByCookieName(name)
}
