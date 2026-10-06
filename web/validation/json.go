// Package validation provides bounded HTTP input decoding.
package validation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	coreerrors "github.com/mrheiz97/stumpfworks-framework/core/errors"
)

// DecodeJSON decodes exactly one JSON value, rejects unknown fields, and caps
// the request body. Returned public messages are safe for API responses.
func DecodeJSON(w http.ResponseWriter, r *http.Request, destination any, maxBytes int64) error {
	if destination == nil {
		return coreerrors.New("invalid_decoder_target", "The server could not process the request")
	}
	if maxBytes <= 0 {
		return coreerrors.New("invalid_body_limit", "The server could not process the request")
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return coreerrors.Wrap("unsupported_media_type", "Content-Type must be application/json", err)
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return decodeError(err)
	}
	err = decoder.Decode(&struct{}{})
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return decodeError(err)
	}
	return coreerrors.New("malformed_json", "Request body must contain exactly one JSON value")
}

func decodeError(err error) error {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		return coreerrors.Wrap("request_too_large", "Request body is too large", err)
	}
	var syntaxError *json.SyntaxError
	if errors.As(err, &syntaxError) || errors.Is(err, io.ErrUnexpectedEOF) {
		return coreerrors.Wrap("malformed_json", "Request body contains malformed JSON", err)
	}
	if errors.Is(err, io.EOF) {
		return coreerrors.Wrap("empty_body", "Request body must not be empty", err)
	}
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &typeError) {
		return coreerrors.Wrap("invalid_json_type", "Request body contains an invalid value type", err)
	}
	return coreerrors.Wrap("invalid_json", "Request body is invalid", fmt.Errorf("decode JSON: %w", err))
}
