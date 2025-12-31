package fido2

import "errors"

// Common errors returned by the fido2 package.
var (
	// ErrPinUvAuthTokenRequired is returned when a PIN or UV auth token is required for an operation.
	ErrPinUvAuthTokenRequired = errors.New("fido2: pinUvAuthToken required")
	// ErrBuiltInUVRequired is returned when built-in user verification is required.
	ErrBuiltInUVRequired = errors.New("fido2: built-in user verification required")
	// ErrNotSupported is returned when an operation or extension is not supported by the device.
	ErrNotSupported = errors.New("fido2: not supported")
	// ErrSyntaxError is returned when there is a syntax error in the request or response.
	ErrSyntaxError = errors.New("fido2: syntax error")
	// ErrBadType is returned when an unexpected type is encountered.
	ErrBadType = errors.New("fido2: bad type")
	// ErrInvalidSaltSize is returned when the salt size for HMAC-secret or PRF is invalid.
	ErrInvalidSaltSize = errors.New("fido2: invalid salt size")
	// ErrPinNotSet is returned when an operation requires a PIN to be set but it is not.
	ErrPinNotSet = errors.New("fido2: pin not set")
	// ErrPinAlreadySet is returned when trying to set a PIN that is already set.
	ErrPinAlreadySet = errors.New("fido2: pin already set")
	// ErrUvNotConfigured is returned when user verification is not configured on the device.
	ErrUvNotConfigured = errors.New("fido2: UV not configured")
	// ErrLargeBlobsIntegrityCheck is returned when the integrity check for large blobs fails.
	ErrLargeBlobsIntegrityCheck = errors.New("fido2: large blobs integrity check failed")
	// ErrLargeBlobsTooBig is returned when the serialized large blobs are too large.
	ErrLargeBlobsTooBig = errors.New("fido2: size of serialized large blobs is too big that token")
)

// ErrorWithMessage represents an error with an additional descriptive message.
type ErrorWithMessage struct {
	Message string
	Err     error
}

// newErrorMessage creates a new ErrorWithMessage.
func newErrorMessage(err error, msg string) *ErrorWithMessage {
	return &ErrorWithMessage{
		Message: msg,
		Err:     err,
	}
}

// Error returns the string representation of the error.
func (m *ErrorWithMessage) Error() string {
	if m.Message != "" {
		return m.Err.Error() + " (" + m.Message + ")"
	}
	return m.Err.Error()
}

// Unwrap returns the underlying error.
func (m *ErrorWithMessage) Unwrap() error {
	return m.Err
}
