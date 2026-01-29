package response_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/bfc-vpn/api/internal/pkg/apperror"
	"github.com/bfc-vpn/api/internal/pkg/response"
)

func setupTestRouter(handler gin.HandlerFunc) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/test", handler)
	
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
	return w
}

func TestError_SetsCorrectContentType(t *testing.T) {
	w := setupTestRouter(func(c *gin.Context) {
		err := apperror.AuthenticationError("Test", "Detail")
		response.Error(c, err)
	})

	assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestNoContent_Returns204(t *testing.T) {
	w := setupTestRouter(func(c *gin.Context) {
		response.NoContent(c)
	})

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestSuccess_Returns200(t *testing.T) {
	w := setupTestRouter(func(c *gin.Context) {
		response.Success(c, map[string]string{"status": "ok"})
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestCreated_Returns201(t *testing.T) {
	w := setupTestRouter(func(c *gin.Context) {
		response.Created(c, map[string]string{"id": "123"})
	})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "123")
}

func TestErrorFromErr_WithAppError(t *testing.T) {
	w := setupTestRouter(func(c *gin.Context) {
		err := apperror.ValidationError("Test", "Detail")
		response.ErrorFromErr(c, err)
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestErrorFromErr_WithStandardError(t *testing.T) {
	w := setupTestRouter(func(c *gin.Context) {
		err := errors.New("standard error")
		response.ErrorFromErr(c, err)
	})

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
