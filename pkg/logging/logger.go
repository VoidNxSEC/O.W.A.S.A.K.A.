package logging

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/config"
)

// Logger wraps zap.SugaredLogger for structured logging
type Logger struct {
	*zap.SugaredLogger
}

// NewLogger creates a new logger from configuration
func NewLogger(cfg *config.LoggingConfig) (*Logger, error) {
	// Parse log level
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	// Create encoder config
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	// Create encoder
	var encoder zapcore.Encoder
	if cfg.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// Create writer sync
	var writeSyncer zapcore.WriteSyncer

	switch cfg.Output {
	case "stdout":
		writeSyncer = zapcore.AddSync(os.Stdout)
	case "file":
		writeSyncer = getFileWriter(cfg)
	case "both":
		writeSyncer = zapcore.NewMultiWriteSyncer(
			zapcore.AddSync(os.Stdout),
			getFileWriter(cfg),
		)
	default:
		writeSyncer = zapcore.AddSync(os.Stdout)
	}

	// Create core
	core := zapcore.NewCore(encoder, writeSyncer, level)

	// Create logger
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1), zap.AddStacktrace(zapcore.ErrorLevel))

	return &Logger{
		SugaredLogger: logger.Sugar(),
	}, nil
}

// parseLevel parses a log level string into zapcore.Level
func parseLevel(levelStr string) (zapcore.Level, error) {
	switch strings.ToLower(levelStr) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	case "dpanic":
		return zapcore.DPanicLevel, nil
	case "panic":
		return zapcore.PanicLevel, nil
	case "fatal":
		return zapcore.FatalLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("unknown log level: %s", levelStr)
	}
}

// getFileWriter creates a file writer with rotation
func getFileWriter(cfg *config.LoggingConfig) zapcore.WriteSyncer {
	lumberjackLogger := &lumberjack.Logger{
		Filename:   cfg.FilePath,
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		Compress:   cfg.Compress,
	}

	return zapcore.AddSync(lumberjackLogger)
}

// WithFields returns a new logger with the given fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	var args []interface{}
	for k, v := range fields {
		args = append(args, k, v)
	}
	return &Logger{
		SugaredLogger: l.With(args...),
	}
}
