// Package apperr defines the error model shared by control plane and data
// plane: a stable machine-readable code, a safe message, and an HTTP status.
// Internal causes are wrapped for errors.Is/As but never serialised.
package apperr

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Error is a classified application error.
type Error struct {
	Code    string
	Message string
	Status  int
	Details map[string]any
	cause   error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.cause)
	}
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.cause }

// Is matches on Code so sentinels can be compared with errors.Is.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// New builds an error.
func New(status int, code, message string) *Error {
	return &Error{Code: code, Message: message, Status: status}
}

// Wrap attaches an internal cause (never sent to clients).
func (e *Error) Wrap(cause error) *Error {
	c := *e
	c.cause = cause
	return &c
}

// WithDetails returns a copy carrying client-safe details.
func (e *Error) WithDetails(d map[string]any) *Error {
	c := *e
	c.Details = d
	return &c
}

// Sentinels. Compare with errors.Is.
var (
	ErrInvalidRequest      = New(http.StatusBadRequest, "invalid_request", "The request is malformed or fails validation.")
	ErrUnauthorized        = New(http.StatusUnauthorized, "unauthorized", "Authentication is required or invalid.")
	ErrForbidden           = New(http.StatusForbidden, "forbidden", "The caller is not allowed to perform this action.")
	ErrNotFound            = New(http.StatusNotFound, "not_found", "The resource does not exist.")
	ErrConflict            = New(http.StatusConflict, "conflict", "The request conflicts with current state.")
	ErrIdempotencyMismatch = New(http.StatusConflict, "idempotency_key_reused", "The idempotency key was used with a different request.")
	ErrPaymentRequired     = New(http.StatusPaymentRequired, "payment_required", "A paid entitlement is required.")
	ErrQuotaExhausted      = New(http.StatusTooManyRequests, "quota_exhausted", "The endpoint has exhausted its monthly transfer allowance.")
	ErrRateLimited         = New(http.StatusTooManyRequests, "rate_limited", "Too many requests.")
	ErrUnavailable         = New(http.StatusServiceUnavailable, "unavailable", "The service is temporarily unavailable.")
	ErrInternal            = New(http.StatusInternalServerError, "internal", "An internal error occurred.")
	ErrGone                = New(http.StatusGone, "gone", "The resource has been released.")
)

// As extracts the *Error from err, or classifies it as internal.
func As(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return ErrInternal.Wrap(err)
}

// Envelope is the JSON error body from the specification (section 10.1).
type Envelope struct {
	Error EnvelopeBody `json:"error"`
}

// EnvelopeBody is the inner object of Envelope.
type EnvelopeBody struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

// Write serialises err as the envelope. Internal errors are reduced to the
// generic message so causes, SQL text and stack details never leak.
func Write(w http.ResponseWriter, err error, requestID string) {
	e := As(err)
	body := Envelope{Error: EnvelopeBody{Code: e.Code, Message: e.Message, RequestID: requestID, Details: e.Details}}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(body)
}
