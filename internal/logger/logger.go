package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var log *zap.SugaredLogger

func Init(production bool) {

	cfg := zap.NewProductionConfig()
	cfg.Encoding = "json"
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if !production {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		cfg.EncoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	}


	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	l, err := cfg.Build(zap.AddCallerSkip(1))
	if err != nil {
		os.Exit(1)
	}
	log = l.Sugar()
}

func Get() *zap.SugaredLogger {
	if log == nil {
		Init(false)
	}
	return log
}

func Sync() {
	if log != nil {
		_ = log.Sync()
	}
}
