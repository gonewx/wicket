// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package phoneverify

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
	// A context that is already done settles the outcome before any work is
	// spent on it — client construction and signing included, which would
	// otherwise run to completion only to fail at the transport.
	if err := ctx.Err(); err != nil {
		return nil, wrapContextError(err)
	}

	// An empty or blank token cannot succeed. Refusing it here spares the
	// shared rate limit a request whose outcome is already known, and matches
	// the closed posture NewVerifier takes towards missing credentials.
	if strings.TrimSpace(token) == "" {
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

	// The client library names tracing spans after the full request URI —
	// token and signature included — whenever a global tracer is registered
	// anywhere in the process. That would hand exactly the text this package
	// redacts to a telemetry pipeline, so tracing is switched off for this
	// client.
	client.SetCloseTrace(true)

	req := dypnsapi.CreateGetMobileRequest()
	// The scheme and host are set explicitly rather than derived from the
	// region, both because the endpoint is a configuration override and
	// because deriving them would reach the vendor's resolution service.
	req.Scheme = v.scheme
	req.Domain = v.host
	req.AccessToken = token
	req.SetReadTimeout(v.timeout)
	req.SetConnectTimeout(v.timeout)

	resp, err := v.exchange(client, req)
	if err != nil {
		if errors.Is(err, ErrMalformedResponse) {
			// Produced by the recover guard in exchange; already classified.
			return nil, err
		}
		return nil, v.classifyCallError(ctx, token, err)
	}

	// A response that names no return code at all is not a rejection the
	// provider expressed — it is a payload this package does not understand,
	// such as an empty body under a success status, which the client library
	// hands back as an untouched zero value.
	if resp.Code == "" {
		return nil, fmt.Errorf("%w: response carried no return code", ErrMalformedResponse)
	}

	// A business failure arrives under a success status with no error at all,
	// carrying its reason in the return code. Branching on the error alone
	// would accept every one of those as a verified phone number. The code,
	// message and request identifier are provider-controlled text: none of it
	// is trusted to be free of echoes or fairly sized, so all three are
	// redacted and bounded before they can reach a caller's log.
	if resp.Code != codeSuccess {
		return nil, &VendorError{
			Code:       truncate(v.redact(resp.Code, token), maxIdentifierTextBytes),
			Message:    truncate(v.redact(resp.Message, token), maxErrorTextBytes),
			RequestID:  truncate(v.redact(resp.RequestId, token), maxIdentifierTextBytes),
			HTTPStatus: resp.GetHttpStatus(),
			category:   classifyVendorCode(resp.Code),
		}
	}

	// A success that carries no number — or nothing but whitespace where one
	// belongs — is a response whose shape is not understood, and a verified
	// phone number is not issued from one.
	if strings.TrimSpace(resp.GetMobileResultDTO.Mobile) == "" {
		return nil, fmt.Errorf("%w: exchange succeeded without a phone number",
			ErrMalformedResponse)
	}

	return &VerifiedPhone{
		Mobile:    resp.GetMobileResultDTO.Mobile,
		RequestID: resp.RequestId,
	}, nil
}

// exchange invokes the operation, converting a decoding panic into a
// malformed-response failure. The client library parses a failure payload
// with unchecked type assertions, so a response whose standard fields carry
// unexpected JSON types — a numeric return code, say — would otherwise bring
// the whole process down.
func (v *verifier) exchange(client *dypnsapi.Client, req *dypnsapi.GetMobileRequest) (resp *dypnsapi.GetMobileResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: vendor library failed decoding the response: %s",
				ErrMalformedResponse, truncate(v.redact(fmt.Sprint(r)), maxErrorTextBytes))
		}
	}()
	return client.GetMobile(req)
}

// classifyCallError categorises a failed exchange.
func (v *verifier) classifyCallError(ctx context.Context, token string, err error) error {
	// A definitive provider response outranks the context. Once this error
	// shape exists, the exchange completed and produced an answer; a deadline
	// that lapsed a moment later must not repaint that answer as retryable,
	// or a caller would resend an already-burned token on the strength of it.
	// A cancellation cannot be hiding in here either — an interrupted request
	// never yields a parsed response.
	var serverErr *sdkerrors.ServerError
	if errors.As(err, &serverErr) {
		category, recognised := lookupVendorCode(serverErr.ErrorCode())
		if !recognised {
			category = classifyHTTPStatus(serverErr.HttpStatus())
		}
		return &VendorError{
			Code:       truncate(v.redact(serverErr.ErrorCode(), token), maxIdentifierTextBytes),
			Message:    truncate(v.redact(serverErr.Message(), token), maxErrorTextBytes),
			RequestID:  truncate(v.redact(serverErr.RequestId(), token), maxIdentifierTextBytes),
			HTTPStatus: serverErr.HttpStatus(),
			category:   category,
		}
	}

	// With no definitive response in hand, a context failure is reported
	// next, because its sentinel is what lets a caller tell its own abort
	// apart from an upstream fault. The context is consulted rather than the
	// returned error, because the client library may have rewritten a
	// cancelled request's error into a timeout of its own.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return wrapContextError(ctxErr)
	}

	// Failures the client library raises about the exchange itself rather
	// than about what the provider said.
	var clientErr *sdkerrors.ClientError
	if errors.As(err, &clientErr) {
		switch clientErr.ErrorCode() {
		case codeDecodeFailure:
			return fmt.Errorf("%w: cannot decode the exchange response: %s",
				ErrMalformedResponse, truncate(v.redact(clientErr.Error(), token), maxErrorTextBytes))
		case codeTimeout:
			// The library only wraps a timeout in this code when its
			// automatic retry is enabled, which this package never turns on;
			// a plain timeout surfaces as a transport failure below and lands
			// on the same category. The branch stays as a guard against the
			// library growing new paths to this code underneath this package.
			return fmt.Errorf("%w: exchange timed out: %s",
				ErrRetryable, truncate(v.redact(clientErr.Error(), token), maxErrorTextBytes))
		default:
			// The remaining codes report a request the library refused to
			// build or send — a missing parameter, an unusable credential,
			// an endpoint it could not resolve. Those are faults on this
			// side, and retrying them changes nothing.
			return fmt.Errorf("%w: exchange could not be issued: %s",
				ErrUnavailable, truncate(v.redact(clientErr.Error(), token), maxErrorTextBytes))
		}
	}

	// Any other failure is a transport failure, and the error it returns
	// embeds the full request URL — key id, token and signature included. It
	// is redacted and flattened into text here rather than wrapped, so no
	// path can reach the original message.
	return fmt.Errorf("%w: exchange request failed: %s",
		ErrRetryable, truncate(v.redact(err.Error(), token), maxErrorTextBytes))
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
