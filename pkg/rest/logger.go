package rest

import (
	"fmt"
	"net/http"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

func NewStructuredLogger() func(next http.Handler) http.Handler {
	return middleware.RequestLogger(&StructuredLogger{})
}

type StructuredLogger struct {
}

func (l *StructuredLogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	args := []interface{}{
		"http_method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent(),
		"uri", fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI),
	}
	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		args = append(args, "req_id", reqID)
	}

	return &StructuredLoggerEntry{
		Logger: log.Logger.With(args...),
	}
}

type StructuredLoggerEntry struct {
	Logger *zap.SugaredLogger
}

func (l *StructuredLoggerEntry) Write(status, bytes int, header http.Header, elapsed time.Duration, extra interface{}) {
	l.Logger.With(
		"resp_status", status,
		"resp_byte_length", bytes,
		"resp_elapsed_ms", float64(elapsed.Nanoseconds())/1000000.0,
	).Info("Request")
}

func (l *StructuredLoggerEntry) Panic(v interface{}, stack []byte) {
	l.Logger.With(
		"stack", string(stack),
		"panic", fmt.Sprintf("%+v", v),
	).Error("Request")
}
