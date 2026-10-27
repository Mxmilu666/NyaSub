package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func writeError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, errorEnvelope{Error: errorBody{Code: code, Message: message}})
}

func writeErrorDetails(c *gin.Context, status int, code, message string, details any) {
	c.AbortWithStatusJSON(status, errorEnvelope{Error: errorBody{Code: code, Message: message, Details: details}})
}

// bindJSON decodes a single JSON object, rejecting unknown fields and trailing
// data. It never echoes the request body (which may contain credentials).
func bindJSON(c *gin.Context, dst any) bool {
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			writeError(c, http.StatusBadRequest, "invalid_request", "request body is required")
			return false
		}
		writeError(c, http.StatusBadRequest, "invalid_request", "invalid JSON request body: "+friendlyJSONError(err))
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(c, http.StatusBadRequest, "invalid_request", "request body must contain exactly one JSON object")
		return false
	}
	return true
}

func friendlyJSONError(err error) string {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return fmt.Sprintf("field %q has the wrong type", typeErr.Field)
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return "malformed JSON"
	}
	if strings.Contains(err.Error(), "unknown field") {
		return err.Error()
	}
	if strings.Contains(err.Error(), "request body too large") {
		return "request body is too large"
	}
	return "malformed JSON"
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || strings.Contains(msg, "constraint failed")
}

func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-_")
	if out == "" {
		return "NyaSub"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}
