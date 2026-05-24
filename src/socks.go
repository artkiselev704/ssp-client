package main

import (
	"errors"
	"net"
)

const (
	SOCKSVersion = 0x05
)

func contains[T comparable](slice []T, value T) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

func SOCKSHandleHandshake(conn net.Conn) error {
	buf := make([]byte, 2)

	_, err := conn.Read(buf)
	if err != nil {
		return err
	}

	if buf[0] != SOCKSVersion {
		_ = SOCKSDoHandshakeReply(conn, 0xFF)
		return errors.New("SOCKS version not supported")
	}

	buf2 := make([]byte, buf[1])

	_, err = conn.Read(buf2)
	if err != nil {
		return err
	}

	if !contains(buf2, 0x00) {
		_ = SOCKSDoHandshakeReply(conn, 0xFF)
		return errors.New("SOCKS method not supported")
	}

	return nil
}

func SOCKSDoHandshakeReply(conn net.Conn, method uint8) error {
	buf := []byte{
		SOCKSVersion, // VER
		method,       // METHOD
	}

	_, err := conn.Write(buf)

	return err
}

func SOCKSHandleRequest(conn net.Conn) ([]byte, []byte, error) {
	buf := make([]byte, 10)

	_, err := conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}

	if buf[0] != SOCKSVersion {
		_ = SOCKSDoRequestReply(conn, 0x01)
		return nil, nil, errors.New("SOCKS version not supported")
	}

	if buf[1] != 0x01 {
		_ = SOCKSDoRequestReply(conn, 0x07)
		return nil, nil, errors.New("SOCKS command not supported")
	}

	if buf[3] != 0x01 {
		_ = SOCKSDoRequestReply(conn, 0x08)
		return nil, nil, errors.New("SOCKS address type not supported")
	}

	return buf[4:8], buf[8:10], nil
}

func SOCKSDoRequestReply(conn net.Conn, reply uint8) error {
	buf := []byte{
		SOCKSVersion,           // VER
		reply,                  // REP
		0x00,                   // RSV
		0x01,                   // ATYP
		0x00, 0x00, 0x00, 0x00, // BND_ADDR
		0x00, 0x00, // BND_PORT
	}

	_, err := conn.Write(buf)

	return err
}
