package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
)

const (
	STCPVersion = 0x01
)

func STCPGetOpCode(conn net.Conn) (uint8, error) {
	slog.Debug("[STCP] GetOpCode")

	buf := make([]byte, 2)

	if _, err := conn.Read(buf); err != nil {
		return 0, err
	}

	if buf[0] != STCPVersion {
		return 0, errors.New(fmt.Sprintf("unsupported STCP version (%d)", buf[0]))
	}

	return buf[1], nil
}

/**
 * 	0x01 - REGISTER
 */

func STCPDoRegister(conn net.Conn, addr []byte, port []byte) error {
	slog.Debug("[STCP] STCPDoRegister")

	buf := []byte{STCPVersion, 0x01}

	tmp := make([]byte, 4)
	copy(tmp, addr)
	buf = append(buf, tmp...)

	tmp = make([]byte, 2)
	copy(tmp, port)
	buf = append(buf, tmp...)

	_, err := conn.Write(buf)
	return err
}

func STCPHandleRegister(conn net.Conn) ([]byte, []byte, error) {
	slog.Debug("[STCP] STCPHandleRegister")

	buf := make([]byte, 6)

	if _, err := conn.Read(buf); err != nil {
		return nil, nil, err
	}

	return buf[0:4], buf[4:6], nil
}

func STCPDoRegisterReply(conn net.Conn, uid []byte) error {
	slog.Debug("[STCP] STCPDoRegisterReply")

	buf := make([]byte, 16)

	copy(buf, uid)

	_, err := conn.Write(buf)
	return err
}

func STCPHandleRegisterReply(conn net.Conn) ([]byte, error) {
	slog.Debug("[STCP] STCPHandleRegisterReply")

	buf := make([]byte, 16)

	if _, err := conn.Read(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

/**
 * 	0x02 - CONTROL
 */

func STCPDoControl(conn net.Conn, uid []byte) error {
	slog.Debug("[STCP] STCPDoControl")

	buf := []byte{STCPVersion, 0x02}

	tmp := make([]byte, 16)
	copy(tmp, uid)
	buf = append(buf, tmp...)

	_, err := conn.Write(buf)
	return err
}

func STCPHandleControl(conn net.Conn) ([]byte, error) {
	slog.Debug("[STCP] STCPHandleControl")

	buf := make([]byte, 16)

	if _, err := conn.Read(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func STCPDoControlReply(conn net.Conn, reply byte) error {
	slog.Debug("[STCP] STCPDoControlReply")

	_, err := conn.Write([]byte{reply})
	return err
}

func STCPHandleControlReply(conn net.Conn) (byte, error) {
	slog.Debug("[STCP] STCPHandleControlReply")

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return 0x00, err
	}

	return buf[0], nil
}

/**
 *	0x03 - PUSH
 */

func STCPDoPush(conn net.Conn, sequenceNum uint8, data []byte, length uint16) error {
	slog.Debug("[STCP] STCPDoPush")

	buf := []byte{STCPVersion, 0x03, sequenceNum}

	buf = binary.BigEndian.AppendUint16(buf, length)

	tmp := make([]byte, length)
	copy(tmp, data)
	buf = append(buf, tmp...)

	_, err := conn.Write(buf)
	return err
}

func STCPHandlePush(conn net.Conn) (uint8, []byte, error) {
	slog.Debug("[STCP] STCPHandlePush")

	buf := make([]byte, 3)

	if _, err := conn.Read(buf); err != nil {
		return 0, nil, err
	}

	data := make([]byte, binary.BigEndian.Uint16(buf[1:]))
	if _, err := conn.Read(data); err != nil {
		return 0, nil, err
	}

	return buf[0], data, nil
}

/**
 *	0x04 - PUSH ACK
 */

func STCPDoPushAck(conn net.Conn, seq uint8) error {
	slog.Debug("[STCP] STCPDoPushAck")
	_, err := conn.Write([]byte{STCPVersion, 0x04, seq})
	return err
}

func STCPHandlePushAck(conn net.Conn) (uint8, error) {
	slog.Debug("[STCP] STCPHandlePushAck")

	buf := make([]byte, 1)

	if _, err := conn.Read(buf); err != nil {
		return 0, err
	}

	return buf[0], nil
}

/**
 *	0x05 - FINISH
 */

func STCPDoFinish(conn net.Conn) error {
	slog.Debug("[STCP] STCPDoFinish")

	_, err := conn.Write([]byte{STCPVersion, 0x05})
	return err
}
