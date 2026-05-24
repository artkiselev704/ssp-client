package main

import (
	"errors"
	"log/slog"
	"net"
	"os"
)

func CloseFile(file *os.File) {
	err := file.Close()
	if err != nil {
		slog.Warn("failed to close file", slog.String("err", err.Error()))
	}
}

func CloseConnection(conn net.Conn) {
	err := conn.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Warn("failed to close connection", slog.String("err", err.Error()))
	}
}
