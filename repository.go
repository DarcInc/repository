package repository

import (
	"fmt"
)

// Error describes an error when reading, writing or creating repositories.
// It retains the original error and an error message to assist in debugging.
type Error struct {
	OriginalError error
	Message       string
}

// Error implements the error interface, returning the string representation
// of the error.
func (re *Error) Error() string {
	return fmt.Sprintf("%s: %v", re.Message, re.OriginalError)
}

// NewError is a convenience method for creating new repository
// errors from a message and original error.
func NewError(err error, message string) *Error {
	return &Error{
		OriginalError: err,
		Message:       message,
	}
}
