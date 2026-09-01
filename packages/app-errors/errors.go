package apperrors

import "errors"

type Code string

const (
	CodeAuthUnauthorized           Code = "auth.unauthorized"
	CodeAuthDevIdentityMissing     Code = "auth.dev_identity_missing"
	CodeConfigInvalid              Code = "config.invalid"
	CodeControlCapacityUnavailable Code = "control.capacity_unavailable"
	CodeControlHostUnreachable     Code = "control.host_unreachable"
	CodeControlInvalidArgument     Code = "control.invalid_argument"
	CodeControlRuntimeUnavailable  Code = "control.runtime_unavailable"
	CodeControlSessionNotFound     Code = "control.session_not_found"
	CodeCoordPayloadTooLarge       Code = "coord.payload_too_large"
	CodeCoordInvalidArgument       Code = "coord.invalid_argument"
	CodeNotFoundOrUnauthorized     Code = "not_found_or_not_authorized"
	CodeNotImplemented             Code = "not_implemented"
	CodePolicyDenied               Code = "policy.denied"
	CodeStorageUnavailable         Code = "storage.unavailable"
)

type Error struct {
	Code    Code
	Layer   string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return e.Message
	}
	return e.Message + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func New(code Code, layer, message string) *Error {
	return &Error{Code: code, Layer: layer, Message: message}
}

func Wrap(code Code, layer, message string, err error) *Error {
	return &Error{Code: code, Layer: layer, Message: message, Err: err}
}

func From(err error) *Error {
	if err == nil {
		return nil
	}
	var appErr *Error
	if errors.As(err, &appErr) {
		return appErr
	}
	return Wrap(CodeStorageUnavailable, "storage", "storage unavailable", err)
}
