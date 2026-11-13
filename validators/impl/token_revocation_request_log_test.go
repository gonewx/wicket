// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

const (
	revocationLogResultMessage = "ValidateRequestAsync result"
	revocationLogClientId      = "revoking.client"
	revocationLogClientName    = "Revoking Client"
	revocationLogRedirectUri   = "https://client.example/cb"
	revocationLogHandle        = "5f0c2a9e7b1d4c38a6e0f4927d3b8c15"
	revocationLogJwt           = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJib2IifQ.c2lnbmF0dXJlLXNlZ21lbnQ"
	// revocationLogPostedSecret is the client secret as a client authenticating
	// in the request body sends it; the validator is handed the whole form.
	revocationLogPostedSecret = "posted-client-secret"
)

// revocationLogFormats are the two handlers of log/slog. They write a value
// handed over as a whole differently, so each is checked on its own. record
// renders the result record as the handler writes it, without the time.
var revocationLogFormats = []struct {
	name       string
	newHandler func(io.Writer, *slog.HandlerOptions) slog.Handler
	record     func(hint string, validationErr error) string
}{
	{
		name: "json",
		newHandler: func(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
			return slog.NewJSONHandler(w, opts)
		},
		record: func(hint string, validationErr error) string {
			errValue := "null"
			if validationErr != nil {
				errValue = strconv.Quote(validationErr.Error())
			}
			return fmt.Sprintf(`{"level":"DEBUG","msg":%q,"clientId":%q,"tokenTypeHint":%q,"error":%s}`,
				revocationLogResultMessage, revocationLogClientId, hint, errValue)
		},
	},
	{
		name: "text",
		newHandler: func(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
			return slog.NewTextHandler(w, opts)
		},
		record: func(hint string, validationErr error) string {
			hintValue, errValue := `""`, "<nil>"
			if hint != "" {
				hintValue = hint
			}
			if validationErr != nil {
				errValue = validationErr.Error()
			}
			return fmt.Sprintf("level=DEBUG msg=%q clientId=%s tokenTypeHint=%s error=%s",
				revocationLogResultMessage, revocationLogClientId, hintValue, errValue)
		},
	},
}

// revocationLogClient returns a client holding a hashed secret, together with
// that hashed value.
func revocationLogClient() (*storage_models.Client, string) {
	hashedSecret := utils.Sha256("revoking-client-secret")

	secret := storage_models.NewSecret()
	secret.Value = hashedSecret

	client := storage_models.NewClient()
	client.ClientId = revocationLogClientId
	client.ClientName = revocationLogClientName
	client.ClientSecrets = []*storage_models.Secret{secret}
	client.RedirectUris = []string{revocationLogRedirectUri}

	return client, hashedSecret
}

func dropLogTime(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) == 0 && attr.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return attr
}

// The result of validating a revocation request is logged at debug level. The
// record names the client, the token type hint and the error, and carries
// neither the token nor anything of the client beyond its id.
func TestTokenRevocationRequestValidatorResultLogCarriesNoCredentials(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		token    string
		hint     string
		wantHint string
		wantErr  error
	}{
		{name: "no hint", token: revocationLogHandle},
		{name: "access token hint", token: revocationLogHandle, hint: wicket.TokenTypeHintsAccessToken, wantHint: wicket.TokenTypeHintsAccessToken},
		{name: "refresh token hint", token: revocationLogHandle, hint: wicket.TokenTypeHintsRefreshToken, wantHint: wicket.TokenTypeHintsRefreshToken},
		{name: "unsupported hint", token: revocationLogHandle, hint: "bogus", wantErr: wicket.RevocationErrorsUnsupportedTokenType},
		{name: "JWT form token", token: revocationLogJwt},
	}

	for _, format := range revocationLogFormats {
		for _, tc := range cases {
			t.Run(format.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				var logs bytes.Buffer
				logger := slog.New(format.newHandler(&logs, &slog.HandlerOptions{
					Level:       slog.LevelDebug,
					ReplaceAttr: dropLogTime,
				}))
				client, hashedSecret := revocationLogClient()

				parameters := url.Values{}
				parameters.Set("token", tc.token)
				parameters.Set("client_id", revocationLogClientId)
				parameters.Set("client_secret", revocationLogPostedSecret)
				if tc.hint != "" {
					parameters.Set("token_type_hint", tc.hint)
				}

				result, err := NewTokenRevocationRequestValidator(logger).ValidateRequest(context.Background(), parameters, client)
				if err != nil {
					t.Fatalf("ValidateRequest error = %v", err)
				}
				if result.Error != tc.wantErr {
					t.Fatalf("result error = %v, want %v", result.Error, tc.wantErr)
				}
				if result.Token != tc.token {
					t.Fatalf("result token = %q, want the submitted token", result.Token)
				}

				var records []string
				for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
					if strings.Contains(line, revocationLogResultMessage) {
						records = append(records, line)
					}
				}
				if len(records) != 1 {
					t.Fatalf("result records = %d, want 1: %s", len(records), logs.String())
				}
				if want := format.record(tc.wantHint, tc.wantErr); records[0] != want {
					t.Errorf("result record = %s, want %s", records[0], want)
				}

				forbidden := []string{tc.token}
				if segments := strings.Split(tc.token, "."); len(segments) > 1 {
					forbidden = append(forbidden, segments...)
				}
				forbidden = append(forbidden,
					revocationLogPostedSecret,
					hashedSecret,
					revocationLogClientName,
					revocationLogRedirectUri,
					// Field names of the client.
					"ClientSecrets", "ClientName", "RedirectUris",
				)
				for _, fragment := range forbidden {
					if strings.Contains(logs.String(), fragment) {
						t.Errorf("log carries %q: %s", fragment, logs.String())
					}
				}
			})
		}
	}
}

// A request that is refused before a result exists is answered as before, and
// what is logged on the way carries neither the token nor the client's secret.
func TestTokenRevocationRequestValidatorRefusalLogCarriesNoCredentials(t *testing.T) {
	t.Parallel()

	posted := func(parameters url.Values) url.Values {
		parameters.Set("client_id", revocationLogClientId)
		parameters.Set("client_secret", revocationLogPostedSecret)
		return parameters
	}

	cases := []struct {
		name          string
		parameters    url.Values
		withoutClient bool
		wantErr       string
		wantResultErr error
		wantRecord    string
	}{
		{name: "no parameters", parameters: url.Values{}, wantErr: "no parameters passed", wantRecord: "no parameters passed"},
		{name: "no client", parameters: posted(url.Values{"token": {revocationLogHandle}}), withoutClient: true, wantErr: "no client passed", wantRecord: "no client passed"},
		{name: "no token", parameters: posted(url.Values{"token_type_hint": {wicket.TokenTypeHintsAccessToken}}), wantResultErr: wicket.TokenErrorsInvalidRequest, wantRecord: "No token found in request"},
		{name: "blank token", parameters: posted(url.Values{"token": {"  "}}), wantResultErr: wicket.TokenErrorsInvalidRequest, wantRecord: "No token found in request"},
	}

	for _, format := range revocationLogFormats {
		for _, tc := range cases {
			t.Run(format.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				var logs bytes.Buffer
				logger := slog.New(format.newHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
				client, hashedSecret := revocationLogClient()
				if tc.withoutClient {
					client = nil
				}

				result, err := NewTokenRevocationRequestValidator(logger).ValidateRequest(context.Background(), tc.parameters, client)
				if tc.wantErr != "" {
					if err == nil || err.Error() != tc.wantErr {
						t.Fatalf("ValidateRequest error = %v, want %q", err, tc.wantErr)
					}
					if result != nil {
						t.Fatalf("result = %+v, want none", result)
					}
				} else {
					if err != nil {
						t.Fatalf("ValidateRequest error = %v", err)
					}
					if result == nil || result.Error != tc.wantResultErr {
						t.Fatalf("result = %+v, want error %v", result, tc.wantResultErr)
					}
					if result.Token != "" || result.Client != nil {
						t.Fatalf("result carries token %q and client %v, want neither", result.Token, result.Client)
					}
				}

				if !strings.Contains(logs.String(), tc.wantRecord) {
					t.Errorf("log does not record %q: %s", tc.wantRecord, logs.String())
				}
				for _, fragment := range []string{revocationLogResultMessage, revocationLogHandle, revocationLogPostedSecret, hashedSecret, "ClientSecrets"} {
					if strings.Contains(logs.String(), fragment) {
						t.Errorf("log carries %q: %s", fragment, logs.String())
					}
				}
			})
		}
	}
}
