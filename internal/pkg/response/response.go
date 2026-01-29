package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
)

// Success sends a successful JSON response
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, data)
}

// Created sends a 201 Created response
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, data)
}

// NoContent sends a 204 No Content response
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Error sends an RFC 7807 error response
func Error(c *gin.Context, err *apperror.AppError) {
	c.Header("Content-Type", "application/problem+json")
	c.JSON(err.Status, err)
}

// ErrorFromErr converts a standard error to AppError and sends response
func ErrorFromErr(c *gin.Context, err error) {
	if appErr, ok := err.(*apperror.AppError); ok {
		Error(c, appErr)
		return
	}
	Error(c, apperror.InternalError(
		"Lỗi không xác định",
		"Vui lòng thử lại sau",
	).WithError(err))
}
