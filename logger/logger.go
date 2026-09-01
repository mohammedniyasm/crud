package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

func NewLogger() *slog.Logger {
	var writer io.Writer = os.Stdout

	file, err := os.OpenFile(
		"logs/app.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	options := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open log file: %v\n", err)
	} else {
		writer = io.MultiWriter(os.Stdout, file)
	}

	handler := slog.NewTextHandler(writer, options)
	return slog.New(handler)
}
