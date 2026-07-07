// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package extensions

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gonewx/wicket"
	models_contexts "github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
)

func HasApplicationFormContentType(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
}

// From: IdentityServer4/src/IdentityServer/Extensions/HttpRequestExtensions.cs
func GetWicketSignoutFrameCallbackUrl(userSession services.UserSession, clock services.SystemClock, urls services.ServerUrls, endSessionMessageStore storage.MessageStore[models_contexts.LogoutNotificationContext], logoutMessage *messages.LogoutMessage) (string, error) {
	user := userSession.GetUser()
	var currentSubId string
	if user != nil {
		currentSubId = GetSubjectIdFromPrincipal(user)
	}

	var endSessionMsg *models_contexts.LogoutNotificationContext

	// if we have a logout message, then that take precedence over the current user
	if logoutMessage != nil && len(logoutMessage.ClientIds) > 0 {
		clientIds := logoutMessage.ClientIds

		// check if current user is same, since we might have new clients (albeit unlikely)
		if currentSubId == logoutMessage.SubjectId {
			clientList, err := userSession.GetClientList()
			if err != nil {
				return "", err
			}

			clientIds = utils.Distinct(append(clientIds, clientList...))
		}

		endSessionMsg = &models_contexts.LogoutNotificationContext{
			SubjectId: logoutMessage.SubjectId,
			ClientIds: clientIds,
			SessionId: logoutMessage.SessionId,
		}

	} else {
		if currentSubId != "" {
			// see if current user has any clients they need to signout of
			clientIds, err := userSession.GetClientList()
			if err != nil {
				return "", err
			}

			if len(clientIds) > 0 {
				endSessionMsg = &models_contexts.LogoutNotificationContext{
					SubjectId: currentSubId,
					ClientIds: clientIds,
					SessionId: userSession.GetSessionId(),
				}
			}
		}
	}

	if endSessionMsg == nil {
		// no sessions, so nothing to cleanup
		return "", nil
	}

	msg := messages.NewMessageWithCreated(endSessionMsg, clock.Now().Unix())

	id, err := endSessionMessageStore.Write(msg)
	if err != nil {
		return "", err
	}

	signoutIframeUrl := utils.EnsureTrailingSlash(urls.BaseUrl()) + gois.ProtocolRoutePathsEndSessionCallback

	u, err := url.Parse(signoutIframeUrl)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Add(gois.UIConstantsDefaultRoutePathParamsEndSessionCallback, id)

	u.RawQuery = q.Encode()

	return u.String(), nil
}

func FilterEmptyValues(values url.Values) url.Values {
	nv := make(url.Values, 0)
	for k, value := range values {
		for _, v := range value {
			if strings.TrimSpace(v) != "" {
				nv.Add(k, v)
			}
		}
	}

	return nv
}
