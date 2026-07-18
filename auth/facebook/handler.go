// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package facebook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf16"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/auth/oauth"
	oauthcore "github.com/gonewx/wicket/auth/oauth/core"
	claimspkg "github.com/gonewx/wicket/claims"
	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/gonewx/wicket/services"
)

type Handler struct {
	*oauthcore.Handler[*Options]
}

func NewHandler(
	opts optspkg.OptionsMonitor[*Options],
	logger *slog.Logger,
	clock services.SystemClock,
) *Handler {
	h := &Handler{}
	h.Handler = oauthcore.NewHandler[*Options](opts, logger, clock)
	h.Handler.Override(h)
	return h
}

// CreateTicket Creates an Ticket from the specified tokens.
func (h *Handler) CreateTicket(identity *claimspkg.ClaimsIdentity, properties *auth.Properties, tokens *oauth.TokenResponse) (*auth.Ticket, error) {
	endpoint, err := url.Parse(h.Options.UserInformationEndpoint())
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Add("access_token", tokens.AccessToken)

	if h.Options.SendAppSecretProof {
		query.Add("appsecret_proof", h.generateAppSecretProof(tokens.AccessToken))
	}

	if len(h.Options.Fields()) > 0 {
		query.Add("fields", strings.Join(h.Options.Fields(), ", "))
	}

	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.Options.Backchannel().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("An error occurred when retrieving Facebook user information (%d). Please check if the authentication information is correct and the corresponding Facebook Graph API is enabled.", resp.StatusCode)
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	ctx, err := oauthcore.NewCreatingTicketContext(claimspkg.NewClaimsPrincipal(
		claimspkg.WithClaimsPrincipalIdentity(identity),
	), properties, h.Request(), h.Response(), h.Scheme, h.Options, h.Options.Backchannel(), tokens, string(payload))
	if err != nil {
		return nil, err
	}
	ctx.RunClaimActions()
	_ = h.Events().CreatingTicket(ctx)

	return auth.NewTicket(ctx.Principal, h.Scheme.Name, ctx.Properties()), nil
}

func (h *Handler) generateAppSecretProof(accessToken string) string {
	algorithm := hmac.New(sha256.New, []byte(h.Options.AppSecret()))

	algorithm.Write([]byte(accessToken))

	proofBytes := algorithm.Sum(nil)

	proof := utf16.Encode([]rune(string(proofBytes)))

	var buf bytes.Buffer
	defer buf.Reset()
	for _, num := range proof {
		buf.WriteString(fmt.Sprintf("%04X", num))
	}

	return buf.String()
}

func (h *Handler) formatScope(scope []string) *string {
	r := h.Handler.FormatScope(scope)
	return &r
}
