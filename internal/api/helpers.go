package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"domain-manager/internal/logger"
	"domain-manager/internal/security"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func ok(c *gin.Context, data any) {
	c.JSON(http.StatusOK, response{Code: 0, Message: "success", Data: data})
}

func created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, response{Code: 0, Message: "success", Data: data})
}

func fail(c *gin.Context, status, code int, message string) {
	c.AbortWithStatusJSON(status, response{Code: code, Message: message})
}

func badRequest(c *gin.Context, message string) {
	fail(c, http.StatusBadRequest, 400, message)
}

func notFound(c *gin.Context, message string) {
	fail(c, http.StatusNotFound, 404, message)
}

func conflict(c *gin.Context, message string) {
	fail(c, http.StatusConflict, 409, message)
}

func serverError(c *gin.Context, err error) {
	if err != nil {
		logger.L().Error("API 处理失败", "error", err, "method", c.Request.Method, "path", c.Request.URL.Path)
		_ = c.Error(err)
	}
	fail(c, http.StatusInternalServerError, 500, "服务器内部错误")
}

func pageParams(c *gin.Context) (page, size int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ = strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return
}

func parseUintParam(c *gin.Context, name string) (uint, bool) {
	v, err := strconv.ParseUint(c.Param(name), 10, 64)
	if err != nil || v == 0 {
		badRequest(c, "ID 参数无效")
		return 0, false
	}
	return uint(v), true
}

func parseDate(value string) (*time.Time, error) {
	return parseDateIn(value, time.Local)
}

func parseDateIn(value string, loc *time.Location) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if loc == nil {
		loc = time.Local
	}
	layouts := []string{time.RFC3339, "2006-01-02", "2006-01-02 15:04:05"}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, value, loc); err == nil {
			return &t, nil
		}
	}
	return nil, errors.New("日期格式无效，请使用 YYYY-MM-DD 或 RFC3339")
}

func paginated(items any, total int64, page, size int) gin.H {
	return gin.H{"items": items, "total": total, "page": page, "page_size": size}
}

func computeDays(t *time.Time) int {
	if t == nil {
		return 0
	}
	return security.DaysUntil(*t)
}

func isNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}
