package main

import (
	"errors"
	"fmt"
	"net"
)

const (
	STCPVersion = 0x01
)

func STCPGetOpCode(conn net.Conn) (uint8, error) {
	buf := make([]byte, 2)

	_, err := conn.Read(buf)
	if err != nil {
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
	buf := make([]byte, 6)

	_, err := conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}

	return buf[0:4], buf[4:6], nil
}

func STCPDoRegisterReply(conn net.Conn, uid []byte) error {
	buf := make([]byte, 16)

	copy(buf, uid)

	_, err := conn.Write(buf)
	return err
}

func STCPHandleRegisterReply(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 16)

	_, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

/**
 * 	0x02 - CONTROL
 */

func STCPDoControl(conn net.Conn, uid []byte) error {
	buf := []byte{STCPVersion, 0x02}

	tmp := make([]byte, 16)
	copy(tmp, uid)
	buf = append(buf, tmp...)

	_, err := conn.Write(buf)
	return err
}

func STCPHandleControl(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 16)

	_, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func STCPDoControlReply(conn net.Conn, ok bool) error {
	var err error

	if ok {
		_, err = conn.Write([]byte{0x01})
	} else {
		_, err = conn.Write([]byte{0x00})
	}

	return err
}

func STCPHandleControlReply(conn net.Conn) (bool, error) {
	buf := make([]byte, 1)

	_, err := conn.Read(buf)
	if err != nil {
		return false, err
	}

	return buf[0] == 0x01, nil
}
