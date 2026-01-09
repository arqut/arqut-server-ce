package api

import (
	"github.com/gofiber/fiber/v2"
)

// SuccessResp sends a successful API response
func SuccessResp(c *fiber.Ctx, data any, meta ...ApiResponseMeta) error {
	resp := ApiResponse{
		Success: true,
		Data:    data,
	}
	if len(meta) > 0 {
		resp.Meta = &meta[0]
	}
	return c.Status(fiber.StatusOK).JSON(&resp)
}

// ErrorResp sends an error API response
func ErrorResp(c *fiber.Ctx, err ApiError, meta ...ApiResponseMeta) error {
	resp := ApiResponse{
		Success: false,
		Error:   &err,
	}
	if len(meta) > 0 {
		resp.Meta = &meta[0]
	}
	status := fiber.StatusBadRequest
	if err.Status != 0 {
		status = err.Status
	}
	return c.Status(status).JSON(&resp)
}

// ErrorCodeResp sends an error response with a specific status code
func ErrorCodeResp(c *fiber.Ctx, httpStatus int, messages ...string) error {
	code := ""
	message := "API Error"
	if len(messages) > 1 {
		code = messages[0]
		message = messages[1]
	} else if len(messages) == 1 {
		message = messages[0]
	}
	return ErrorResp(c, ApiError{
		Code:    code,
		Message: message,
		Status:  httpStatus,
	})
}

// ErrorNotFoundResp sends a 404 Not Found error response
func ErrorNotFoundResp(c *fiber.Ctx, messages ...string) error {
	return ErrorCodeResp(c, fiber.StatusNotFound, messages...)
}

// ErrorUnauthorizedResp sends a 401 Unauthorized error response
func ErrorUnauthorizedResp(c *fiber.Ctx, messages ...string) error {
	return ErrorCodeResp(c, fiber.StatusUnauthorized, messages...)
}

// ErrorBadRequestResp sends a 400 Bad Request error response
func ErrorBadRequestResp(c *fiber.Ctx, messages ...string) error {
	return ErrorCodeResp(c, fiber.StatusBadRequest, messages...)
}

// ErrorInternalServerErrorResp sends a 500 Internal Server Error response
func ErrorInternalServerErrorResp(c *fiber.Ctx, messages ...string) error {
	return ErrorCodeResp(c, fiber.StatusInternalServerError, messages...)
}
