package api

import "github.com/arqut/arqut-server-ce/internal/middleware"

// MakeResponse creates a standard API response
func MakeResponse(data interface{}, err interface{}, message string) middleware.Response {
	return middleware.MakeResponse(data, err, message)
}
