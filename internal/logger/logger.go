package logger

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	legolog "github.com/go-acme/lego/v4/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

var normalLogger *slog.Logger

// Setup configures structured logging to stdout and a rotating file.
func Setup(logDir, level string) (*slog.Logger, error) {
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}
	rotator := &lumberjack.Logger{
		Filename:   filepath.Join(logDir, "domain-manager.log"),
		MaxSize:    50,
		MaxBackups: 10,
		MaxAge:     30,
		Compress:   true,
		LocalTime:  true,
	}
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	writer := io.MultiWriter(os.Stdout, rotator)
	handler := slog.NewTextHandler(writer, &slog.HandlerOptions{Level: lvl})
	normalLogger = slog.New(handler)
	slog.SetDefault(normalLogger)
	legolog.Logger = legoAdapter{l: normalLogger}
	return normalLogger, nil
}

func L() *slog.Logger {
	if normalLogger == nil {
		return slog.Default()
	}
	return normalLogger
}

type legoAdapter struct{ l *slog.Logger }

func (a legoAdapter) output(level slog.Level, args ...any) {
	msg := strings.TrimSpace(fmt.Sprint(args...))
	if msg != "" {
		a.l.Log(context.Background(), level, "acme: "+msg)
	}
}

func (a legoAdapter) Fatal(args ...any)   { a.output(slog.LevelError, args...); os.Exit(1) }
func (a legoAdapter) Fatalln(args ...any) { a.output(slog.LevelError, args...); os.Exit(1) }
func (a legoAdapter) Fatalf(format string, args ...any) {
	a.output(slog.LevelError, fmt.Sprintf(format, args...))
	os.Exit(1)
}
func (a legoAdapter) Print(args ...any)   { a.output(slog.LevelInfo, args...) }
func (a legoAdapter) Println(args ...any) { a.output(slog.LevelInfo, args...) }
func (a legoAdapter) Printf(format string, args ...any) {
	a.output(slog.LevelInfo, fmt.Sprintf(format, args...))
}

// StandardLogger exposes a stdlib logger backing the application log file.
func StandardLogger() *log.Logger {
	return log.New(&slogWriter{}, "", 0)
}

type slogWriter struct{}

func (slogWriter) Write(p []byte) (int, error) {
	L().Info(strings.TrimSpace(string(p)))
	return len(p), nil
}
