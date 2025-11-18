package api

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

// Map is an alias for map[string]interface{}
// Note: In production, this would import from github.com/arqut/common/types
type Map map[string]interface{}

// Pagination contains pagination metadata
type Pagination struct {
	Page       int `json:"page"`
	PerPage    int `json:"perPage"`
	Total      int `json:"total"`
	TotalPages int `json:"totalPages"`
}

// ApiResponseMeta contains metadata for API responses
type ApiResponseMeta struct {
	RequestID  string      `json:"requestId,omitempty"`
	Timestamp  *time.Time  `json:"timestamp,omitempty"`
	Ordering   *Map        `json:"ordering,omitempty"`
	Pagination *Pagination `json:"pagination,omitempty"`
}

// ApiError represents a structured API error
type ApiError struct {
	Code    int         `json:"code,omitempty"`
	Message string      `json:"message,omitempty"`
	Detail  interface{} `json:"detail,omitempty"`
}

// ApiResponse is the standard API response structure
type ApiResponse struct {
	Success bool             `json:"success"`
	Data    interface{}      `json:"data,omitempty"`
	Error   *ApiError        `json:"error,omitempty"`
	Meta    *ApiResponseMeta `json:"meta,omitempty"`
}

// SuccessResp returns a successful response with optional metadata
func SuccessResp(c *fiber.Ctx, data interface{}, meta ...ApiResponseMeta) error {
	resp := ApiResponse{
		Success: true,
		Data:    data,
	}
	if len(meta) > 0 {
		resp.Meta = &meta[0]
	}
	return c.Status(fiber.StatusOK).JSON(&resp)
}

// ErrorResp returns an error response with optional metadata
func ErrorResp(c *fiber.Ctx, err ApiError, meta ...ApiResponseMeta) error {
	resp := ApiResponse{
		Success: false,
		Error:   &err,
	}
	if len(meta) > 0 {
		resp.Meta = &meta[0]
	}
	code := fiber.StatusBadRequest
	if err.Code != 0 {
		code = err.Code
	}
	return c.Status(code).JSON(&resp)
}

// ErrorCodeResp returns an error response with a specific HTTP status code
func ErrorCodeResp(c *fiber.Ctx, code int, message ...string) error {
	msg := "API Error"
	if len(message) > 0 {
		msg = message[0]
	}
	return ErrorResp(c, ApiError{
		Code:    code,
		Message: msg,
	})
}

// ErrorNotFoundResp returns a 404 Not Found error response
func ErrorNotFoundResp(c *fiber.Ctx, message ...string) error {
	return ErrorCodeResp(c, fiber.StatusNotFound, message...)
}

// ErrorUnauthorizedResp returns a 401 Unauthorized error response
func ErrorUnauthorizedResp(c *fiber.Ctx, message ...string) error {
	return ErrorCodeResp(c, fiber.StatusUnauthorized, message...)
}

// ErrorBadRequestResp returns a 400 Bad Request error response
func ErrorBadRequestResp(c *fiber.Ctx, message ...string) error {
	return ErrorCodeResp(c, fiber.StatusBadRequest, message...)
}

// ErrorInternalServerErrorResp returns a 500 Internal Server Error response
func ErrorInternalServerErrorResp(c *fiber.Ctx, message ...string) error {
	return ErrorCodeResp(c, fiber.StatusInternalServerError, message...)
}
