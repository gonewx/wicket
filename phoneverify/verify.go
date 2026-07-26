// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package phoneverify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	sdkerrors "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/dypnsapi"
)

// endpointDataOnce warms the client library's package-level endpoint table
// exactly once.
//
// Building a client copies that table into it, and the library fills the table
// in on first use with an unsynchronised nil check followed by an assignment.
// Two exchanges starting at the same time therefore race on it — in the
// construction step, before either has a client of its own, so building one
// client per call does not by itself avoid the race. Warming the table behind a
// one-shot guard turns every later construction into a read of an already
// populated table, and the guard supplies the ordering that makes those reads
// safe.
var endpointDataOnce sync.Once

// warmEndpointData populates the library's endpoint table before any concurrent
// construction can reach it.
func warmEndpointData() {
	endpointDataOnce.Do(func() { dypnsapi.GetEndpointMap() })
}

// contextTransport carries a call's context into a request the client library
// builds on its own.
//
// The operation invoked here takes no context of its own, so a caller's
// cancellation would otherwise reach nothing and an abandoned exchange would
// run to its transport timeout. Attaching the context at the round trip is what
// makes cancellation actually interrupt the request in flight.
//
// The type is deliberately not the standard concrete transport: the client
// library rewrites a transport of that type to install its own dial timeout,
// and leaves any other implementation alone. The connect timeout is therefore
// not applied through the dialer; the context and the client-level timeout
// bound the exchange instead.
type contextTransport struct {
	ctx  context.Context
	base http.RoundTripper
}

func (t *contextTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(r.WithContext(t.ctx))
}

// Verify exchanges an authentication token for the phone number behind it.
func (v *verifier) Verify(ctx context.Context, token string) (*VerifiedPhone, error) {
	// An empty token cannot succeed. Refusing it here spares the shared rate
	// limit a request whose outcome is already known, and matches the closed
	// posture NewVerifier takes towards missing credentials.
	if token == "" {
		if err := ctx.Err(); err != nil {
			return nil, wrapContextError(err)
		}
		return nil, fmt.Errorf("%w: authentication token is empty", ErrInvalidCredential)
	}

	// The client is built for this one call and not retained. The library
	// writes the shared client's timeout and transport on every request, so a
	// client held across concurrent exchanges is a data race by construction.
	// Building one per call costs a few tens of microseconds, which is far
	// below the cost of the network round trip it precedes.
	warmEndpointData()
	client, err := dypnsapi.NewClientWithAccessKey(v.regionID, v.accessKeyID, v.accessKeySecret)
	if err != nil {
		// No exchange took place: the credentials could not even be turned
		// into a client, which is a fault on this side. The message may quote
		// the values it was given, so it cannot be surfaced verbatim.
		return nil, fmt.Errorf("%w: cannot build the vendor client: %s",
			ErrUnavailable, truncate(v.redact(err.Error()), maxErrorTextBytes))
	}
	defer client.Shutdown()

	client.SetTransport(&contextTransport{ctx: ctx, base: http.DefaultTransport})

	req := dypnsapi.CreateGetMobileRequest()
	// The scheme and host are set explicitly rather than derived from the
	// region, both because the endpoint is a configuration override and
	// because deriving them would reach the vendor's resolution service.
	req.Scheme = v.scheme
	req.Domain = v.host
	req.AccessToken = token
	req.SetReadTimeout(v.timeout)
	req.SetConnectTimeout(v.timeout)

	resp, err := client.GetMobile(req)
	if err != nil {
		return nil, v.classifyCallError(ctx, err)
	}

	// A business failure arrives under a success status with no error at all,
	// carrying its reason in the return code. Branching on the error alone
	// would accept every one of those as a verified phone number.
	if resp.Code != codeSuccess {
		return nil, &VendorError{
			Code:       resp.Code,
			Message:    truncate(v.redact(resp.Message), maxErrorTextBytes),
			RequestID:  resp.RequestId,
			HTTPStatus: resp.GetHttpStatus(),
			category:   classifyVendorCode(resp.Code),
		}
	}

	// A success that carries no number is a response whose shape is not
	// understood, and a verified phone number is not issued from one.
	if resp.GetMobileResultDTO.Mobile == "" {
		return nil, fmt.Errorf("%w: exchange succeeded without a phone number",
			ErrMalformedResponse)
	}

	return &VerifiedPhone{
		Mobile:    resp.GetMobileResultDTO.Mobile,
		RequestID: resp.RequestId,
	}, nil
}

// classifyCallError categorises a failed exchange.
func (v *verifier) classifyCallError(ctx context.Context, err error) error {
	// A context failure is reported before anything else, because its
	// sentinel is what lets a caller tell its own abort apart from an
	// upstream fault. The context is consulted rather than the returned
	// error, because the client library may have rewritten a cancelled
	// request's error into a timeout of its own.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return wrapContextError(ctxErr)
	}

	// A non-success status is reported as a server-side failure carrying the
	// return code, message and status parsed out of the response.
	var serverErr *sdkerrors.ServerError
	if errors.As(err, &serverErr) {
		category, recognised := lookupVendorCode(serverErr.ErrorCode())
		if !recognised {
			category = classifyHTTPStatus(serverErr.HttpStatus())
		}
		return &VendorError{
			Code:       serverErr.ErrorCode(),
			Message:    truncate(v.redact(serverErr.Message()), maxErrorTextBytes),
			RequestID:  serverErr.RequestId(),
			HTTPStatus: serverErr.HttpStatus(),
			category:   category,
		}
	}

	// Failures the client library raises about the exchange itself rather
	// than about what the provider said.
	var clientErr *sdkerrors.ClientError
	if errors.As(err, &clientErr) {
		switch clientErr.ErrorCode() {
		case codeDecodeFailure:
			return fmt.Errorf("%w: cannot decode the exchange response: %s",
				ErrMalformedResponse, truncate(v.redact(clientErr.Error()), maxErrorTextBytes))
		case codeTimeout:
			return fmt.Errorf("%w: exchange timed out: %s",
				ErrRetryable, truncate(v.redact(clientErr.Error()), maxErrorTextBytes))
		default:
			// The remaining codes report a request the library refused to
			// build or send — a missing parameter, an unusable credential,
			// an endpoint it could not resolve. Those are faults on this
			// side, and retrying them changes nothing.
			return fmt.Errorf("%w: exchange could not be issued: %s",
				ErrUnavailable, truncate(v.redact(clientErr.Error()), maxErrorTextBytes))
		}
	}

	// Any other failure is a transport failure, and the error it returns
	// embeds the full request URL — key id and signature included. It is
	// redacted and flattened into text here rather than wrapped, so no path
	// can reach the original message.
	return fmt.Errorf("%w: exchange request failed: %s",
		ErrRetryable, truncate(v.redact(err.Error()), maxErrorTextBytes))
}

// wrapContextError preserves a context failure's own sentinel. A deadline is
// additionally advertised as retryable, since the same exchange may well
// succeed given more time; a cancellation is not, because retrying it would
// contradict the instruction that produced it.
func wrapContextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: exchange aborted by caller", context.Canceled)
	}
	return fmt.Errorf("%w: %w", ErrRetryable, err)
}
