package main

import (
	"encoding/binary"
	"errors"
	"log/slog"
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
	slog.Debug("[SOCKS] SOCKSHandleHandshake")

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
	slog.Debug("[SOCKS] SOCKSDoHandshakeReply")

	buf := []byte{
		SOCKSVersion, // VER
		method,       // METHOD
	}

	_, err := conn.Write(buf)

	return err
}

func SOCKSHandleRequest(conn net.Conn) (string, uint16, uint8, error) {
	slog.Debug("[SOCKS] SOCKSHandleRequest")

	buf := make([]byte, 4)

	if _, err := conn.Read(buf); err != nil {
		return "", 0, 0, err
	}

	if buf[0] != SOCKSVersion {
		_ = SOCKSDoRequestReply(conn, 0x01, 0x01, "", 0)
		return "", 0, 0, errors.New("version not supported")
	}

	if buf[1] != 0x01 {
		_ = SOCKSDoRequestReply(conn, 0x07, 0x01, "", 0)
		return "", 0, 0, errors.New("command not supported")
	}

	var (
		addr string
		port uint16
	)

	switch buf[3] {
	case 0x01: // IPv4
		hostBuf := make([]byte, 6)
		if _, err := conn.Read(hostBuf); err != nil {
			_ = SOCKSDoRequestReply(conn, 0x01, 0x01, "", 0)
			return "", 0, 0, err
		}

		ipv4 := net.IP(hostBuf[:4]).To4()
		if ipv4 == nil {
			_ = SOCKSDoRequestReply(conn, 0x01, 0x01, "", 0)
			return "", 0, 0, errors.New("invalid IPv4 address")
		}

		addr = ipv4.String()
		port = binary.BigEndian.Uint16(hostBuf[4:6])
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := conn.Read(lenBuf); err != nil {
			_ = SOCKSDoRequestReply(conn, 0x01, 0x01, "", 0)
			return "", 0, 0, err
		}

		hostBuf := make([]byte, lenBuf[0]+2)
		if _, err := conn.Read(hostBuf); err != nil {
			_ = SOCKSDoRequestReply(conn, 0x01, 0x01, "", 0)
			return "", 0, 0, err
		}

		addr = string(hostBuf[:lenBuf[0]])
		port = binary.BigEndian.Uint16(hostBuf[lenBuf[0] : lenBuf[0]+2])
	case 0x04: // IPv6
		hostBuf := make([]byte, 18)
		if _, err := conn.Read(hostBuf); err != nil {
			_ = SOCKSDoRequestReply(conn, 0x01, 0x01, "", 0)
			return "", 0, 0, err
		}

		ipv6 := net.IP(hostBuf[:16]).To16()
		if ipv6 == nil {
			_ = SOCKSDoRequestReply(conn, 0x01, 0x01, "", 0)
			return "", 0, 0, errors.New("invalid IPv6 address")
		}

		addr = ipv6.String()
		port = binary.BigEndian.Uint16(hostBuf[16:18])
	default:
		_ = SOCKSDoRequestReply(conn, 0x01, 0x01, "", 0)
		return "", 0, 0, errors.New("address type not supported")
	}

	return addr, port, buf[3], nil
}

func SOCKSDoRequestReply(conn net.Conn, reply uint8, atyp uint8, addr string, port uint16) error {
	slog.Debug("[SOCKS] SOCKSDoRequestReply")

	buf := []byte{
		SOCKSVersion, // VER
		reply,        // REP
		0x00,         // RSV
		atyp,         // ATYP
	}

	// addr
	switch atyp {
	case 0x01:
		ip := net.ParseIP(addr)
		if ip == nil {
			return errors.New("invalid IP address")
		}

		ipv4 := ip.To4()
		if ipv4 == nil {
			return errors.New("invalid IPv4 address")
		}

		buf = append(buf, ipv4...)
		buf = binary.BigEndian.AppendUint16(buf, port)
	case 0x03:
		length := len(addr)
		if length > 255 {
			return errors.New("address string is too long")
		}

		buf = append(buf, byte(length))
		buf = append(buf, addr...)
		buf = binary.BigEndian.AppendUint16(buf, port)
	case 0x04:
		ip := net.ParseIP(addr)
		if ip == nil {
			return errors.New("invalid IP address")
		}

		ipv6 := ip.To16()
		if ipv6 == nil {
			return errors.New("invalid IPv6 address")
		}

		buf = append(buf, ipv6...)
		buf = binary.BigEndian.AppendUint16(buf, port)
	default:
		return errors.New("address type not supported")
	}

	_, err := conn.Write(buf)
	return err
}
