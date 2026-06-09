package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
)

const (
	STCPVersion = 0x01
)

func STCPGetOpCode(conn net.Conn) (uint8, error) {
	slog.Debug("[STCP] GetOpCode BEGIN")

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}

	if buf[0] != STCPVersion {
		return 0, fmt.Errorf("unsupported version (%d)", buf[0])
	}

	slog.Debug("[STCP] GetOpCode", slog.Int("opcode", int(buf[1])))
	return buf[1], nil
}

/**
 * 	0x01 - REGISTER
 */

func STCPDoRegister(conn net.Conn, addr string, port uint16) error {
	slog.Debug("[STCP] STCPDoRegister", slog.String("addr", addr), slog.Int("port", int(port)))

	if len(addr) > 255 {
		return fmt.Errorf("address string is too long")
	}

	buf := []byte{STCPVersion, 0x01, byte(len(addr))}
	buf = append(buf, addr...)
	buf = binary.BigEndian.AppendUint16(buf, port)

	_, err := conn.Write(buf)
	return err
}

func STCPHandleRegister(conn net.Conn) (string, uint16, error) {
	slog.Debug("[STCP] STCPHandleRegister BEGIN")

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", 0, err
	}

	hostBuf := make([]byte, buf[0]+2)
	if _, err := io.ReadFull(conn, hostBuf); err != nil {
		return "", 0, err
	}

	addr := string(hostBuf[:buf[0]])
	port := binary.BigEndian.Uint16(hostBuf[buf[0] : buf[0]+2])

	slog.Debug("[STCP] STCPHandleRegister", slog.String("addr", addr), slog.Int("port", int(port)))
	return addr, port, nil
}

func STCPDoRegisterReply(conn net.Conn, uid []byte) error {
	slog.Debug("[STCP] STCPDoRegisterReply", slog.String("uid", string(uid)))

	buf := make([]byte, 16)

	copy(buf, uid)

	_, err := conn.Write(buf)
	return err
}

func STCPHandleRegisterReply(conn net.Conn) ([]byte, error) {
	slog.Debug("[STCP] STCPHandleRegisterReply BEGIN")

	buf := make([]byte, 16)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	slog.Debug("[STCP] STCPHandleRegisterReply", slog.String("uid", string(buf)))
	return buf, nil
}

/**
 * 	0x02 - CONTROL
 */

func STCPDoControl(conn net.Conn, uid []byte) error {
	slog.Debug("[STCP] STCPDoControl", slog.String("uid", string(uid)))

	buf := []byte{STCPVersion, 0x02}

	tmp := make([]byte, 16)
	copy(tmp, uid)
	buf = append(buf, tmp...)

	_, err := conn.Write(buf)
	return err
}

func STCPHandleControl(conn net.Conn) ([]byte, error) {
	slog.Debug("[STCP] STCPHandleControl BEGIN")

	buf := make([]byte, 16)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	slog.Debug("[STCP] STCPHandleControl", slog.String("uid", string(buf)))
	return buf, nil
}

func STCPDoControlReply(conn net.Conn, reply byte) error {
	slog.Debug("[STCP] STCPDoControlReply", slog.Int("reply", int(reply)))

	_, err := conn.Write([]byte{reply})
	return err
}

func STCPHandleControlReply(conn net.Conn) (byte, error) {
	slog.Debug("[STCP] STCPHandleControlReply BEGIN")

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0x00, err
	}

	slog.Debug("[STCP] STCPHandleControlReply", slog.Int("reply", int(buf[0])))
	return buf[0], nil
}

/**
 *	0x03 - PUSH
 */

func STCPDoPush(conn net.Conn, sequenceNum uint8, data []byte, length uint16) error {
	slog.Debug("[STCP] STCPDoPush", slog.Int("sequenceNum", int(sequenceNum)), slog.Int("length", int(length)))

	buf := []byte{STCPVersion, 0x03, sequenceNum}

	buf = binary.BigEndian.AppendUint16(buf, length)

	tmp := make([]byte, length)
	copy(tmp, data)
	buf = append(buf, tmp...)

	_, err := conn.Write(buf)
	return err
}

func STCPHandlePush(conn net.Conn) (uint8, []byte, error) {
	slog.Debug("[STCP] STCPHandlePush BEGIN")

	buf := make([]byte, 3)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, nil, err
	}

	dataBuf := make([]byte, binary.BigEndian.Uint16(buf[1:]))
	if _, err := io.ReadFull(conn, dataBuf); err != nil {
		return 0, nil, err
	}

	slog.Debug("[STCP] STCPHandlePush", slog.Int("sequenceNum", int(buf[0])), slog.Int("length", len(dataBuf)))
	return buf[0], dataBuf, nil
}

/**
 *	0x04 - PUSH ACK
 */

func STCPDoPushAck(conn net.Conn, sequenceNum uint8) error {
	slog.Debug("[STCP] STCPDoPushAck", slog.Int("sequenceNum", int(sequenceNum)))
	_, err := conn.Write([]byte{STCPVersion, 0x04, sequenceNum})
	return err
}

func STCPHandlePushAck(conn net.Conn) (uint8, error) {
	slog.Debug("[STCP] STCPHandlePushAck BEGIN")

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}

	slog.Debug("[STCP] STCPHandlePushAck", slog.Int("sequenceNum", int(buf[0])))
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
