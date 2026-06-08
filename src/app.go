package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"runtime"
	"time"
)

var (
	gConfig    Config
	gTLSConfig tls.Config
)

type Config struct {
	Host     string   `json:"host"`
	Servers  []string `json:"servers"`
	Retries  int      `json:"retries"`
	Timeout  int      `json:"timeout"`
	LogLevel int      `json:"log_level"`
}

type DataPacket struct {
	length uint16
	data   []byte
}

func LoadConfig() error {
	// Read config.json
	file, err := os.Open("config.json")
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	err = json.NewDecoder(file).Decode(&gConfig)
	if err != nil {
		return err
	}

	// Read certificate
	cert, err := os.ReadFile("cert.crt")
	if err != nil {
		return err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cert)

	gTLSConfig = tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: true,
	}

	return nil
}

func GetConnection() (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: time.Duration(gConfig.Timeout) * time.Second,
		},
		Config: &gTLSConfig,
	}
	return dialer.Dial("tcp", gConfig.Servers[rand.Intn(len(gConfig.Servers))])
}

func DoRegister(addr []byte, port []byte) (net.Conn, []byte, error) {
	for i := 0; i < gConfig.Retries; i++ {
		tgtConn, err := GetConnection()
		if err != nil {
			slog.Debug("DoRegister -> GetConnection error", slog.String("err", err.Error()))
			continue
		}

		err = STCPDoRegister(tgtConn, addr, port)
		if err != nil {
			slog.Debug("DoRegister -> STCPDoRegister error", slog.String("err", err.Error()))
			_ = tgtConn.Close()
			continue
		}

		uid, err := STCPHandleRegisterReply(tgtConn)
		if err != nil {
			slog.Debug("DoRegister -> STCPHandleRegisterReply error", slog.String("err", err.Error()))
			_ = tgtConn.Close()
			continue
		}

		return tgtConn, uid, nil
	}

	return nil, nil, errors.New("retries limit exceeded")
}

func DoExchange(srcConn net.Conn, tgtConn net.Conn, uid []byte) error {
	// Setup global
	var (
		sequenceNum uint8  = 0
		pendingData []byte = nil
	)

	// Setup source
	var (
		srcErrCh     = make(chan error, 10)
		srcInDataCh  = make(chan []byte, 1)
		srcOutDataCh = make(chan []byte, 1)
	)
	srcCtx, srcCancel := context.WithCancel(context.Background())
	defer srcCancel()

	go func() { // reader
		for {
			buf := make([]byte, 4096)
			n, err := srcConn.Read(buf)
			if err != nil {
				srcErrCh <- err
				return
			}
			if n > 0 {
				select {
				case srcInDataCh <- buf[:n]:
				case <-srcCtx.Done():
					return
				}
			}
		}
	}()

	go func() { // writer
		for {
			select {
			case data := <-srcOutDataCh:
				if _, err := srcConn.Write(data); err != nil {
					srcErrCh <- err
					return
				}
			case <-srcCtx.Done():
				return
			}
		}
	}()

	// Connect to the target
	for i := 0; i < gConfig.Retries; i++ {
		// Reconnect
		if tgtConn == nil {
			var err error
			if tgtConn, err = GetConnection(); err != nil {
				slog.Debug("DoExchange -> GetConnection error", slog.String("err", err.Error()))
				continue
			}
		}

		// Control
		if err := STCPDoControl(tgtConn, uid); err != nil {
			slog.Debug("DoExchange -> STCPDoControl error", slog.String("err", err.Error()))
			tgtConn.Close()
			tgtConn = nil
			continue
		}

		// Check control reply
		reply, err := STCPHandleControlReply(tgtConn)
		if err != nil {
			slog.Debug("DoExchange -> STCPHandleControlReply error", slog.String("err", err.Error()))
			tgtConn.Close()
			tgtConn = nil
			continue
		}

		// If reply not successful, finish session
		if reply != 0x01 {
			slog.Debug("failed to take control", slog.Int("reply", int(reply)))
			return nil
		}

		// Reset attempts
		i = 0

		// Exchange data
		var (
			ackCh    = make(chan struct{}, 1)
			tgtErrCh = make(chan error, 10)
		)
		tgtCtx, tgtCancel := context.WithCancel(srcCtx)

		go func() { // target writer
			for {
				// Read from source
				if pendingData == nil {
					select {
					case pendingData = <-srcInDataCh:
					case <-tgtCtx.Done():
						return
					}
				}

				// Write to target
				if err := STCPDoPush(tgtConn, sequenceNum, pendingData, uint16(len(pendingData))); err != nil {
					tgtErrCh <- err
					return
				}

				// Wait for ACK
				select {
				case <-tgtCtx.Done():
					return
				case <-ackCh:
					pendingData = nil
					sequenceNum++
				}
			}
		}()

		go func() { // target reader
			for {
				opcode, err := STCPGetOpCode(tgtConn)
				if err != nil {
					tgtErrCh <- err
					return
				}

				switch opcode {
				case 0x03: // PUSH
					// Handle push
					inSequenceNum, data, err := STCPHandlePush(tgtConn)
					if err != nil {
						tgtErrCh <- err
						return
					}

					// Write to source
					select {
					case srcOutDataCh <- data:
					case <-tgtCtx.Done():
						return
					}

					// Confirm push
					if err := STCPDoPushAck(tgtConn, inSequenceNum); err != nil {
						tgtErrCh <- err
						return
					}
				case 0x04: // PUSH ACK
					// Handle PUSH ACK
					inSequenceNum, err := STCPHandlePushAck(tgtConn)
					if err != nil {
						tgtErrCh <- err
						return
					}

					// Compare numbers
					if inSequenceNum != sequenceNum {
						slog.Debug("inSequenceNum != sequenceNum",
							slog.Int("sequenceNum", int(sequenceNum)),
							slog.Int("inSequenceNum", int(inSequenceNum)),
						)
						continue
					}

					// Confirm ACK
					select {
					case ackCh <- struct{}{}:
					case <-tgtCtx.Done():
					}
				default:
					tgtErrCh <- fmt.Errorf("unknown opcode: %d", opcode)
					return
				}
			}
		}()

		// Handle events
		doExit := false

		select {
		case <-tgtCtx.Done():
			doExit = true
		case err := <-srcErrCh:
			slog.Debug("DoExchange -> srcErrCh", slog.String("err", err.Error()))
			doExit = true
		case err := <-tgtErrCh:
			slog.Debug("DoExchange -> tgtErrCh", slog.String("err", err.Error()))
		}

		tgtCancel()
		tgtConn.Close()
		tgtConn = nil

		if doExit {
			return nil
		}
	}

	return errors.New("retries limit exceeded")
}

func HandleSession(srcConn net.Conn) {
	// Handle current session
	slog.Info("new session", slog.String("srcAddr", srcConn.RemoteAddr().String()))
	defer func() {
		slog.Debug("session closed", slog.Int("goroutine_num", runtime.NumGoroutine()))
		_ = srcConn.Close()
	}()

	// Handle SOCKS handshake
	err := SOCKSHandleHandshake(srcConn)
	if err != nil {
		slog.Debug("SOCKSHandleHandshake error", slog.String("err", err.Error()))
		return
	}

	// Select SOCKS method
	err = SOCKSDoHandshakeReply(srcConn, 0x00)
	if err != nil {
		slog.Debug("SOCKSDoHandshakeReply error", slog.String("err", err.Error()))
		return
	}

	// Handle SOCKS request
	tgtAddr, tgtPort, err := SOCKSHandleRequest(srcConn)
	if err != nil {
		slog.Debug("SOCKSHandleRequest error", slog.String("err", err.Error()))
		return
	}

	// Confirm SOCKS connection
	err = SOCKSDoRequestReply(srcConn, 0x00)
	if err != nil {
		slog.Error("SOCKSDoRequestReply error", slog.String("err", err.Error()))
		return
	}

	// Register session
	tgtConn, uid, err := DoRegister(tgtAddr, tgtPort)
	if err != nil {
		slog.Debug("DoRegister error", slog.String("err", err.Error()))
		return
	}

	// Begin exchange
	err = DoExchange(srcConn, tgtConn, uid)
	if err != nil {
		slog.Debug("DoExchange error", slog.String("err", err.Error()))
		return
	}
}

func main() {
	// Load config
	err := LoadConfig()
	if err != nil {
		slog.Error("failed to load config", slog.String("err", err.Error()))
		os.Exit(1)
	}

	slog.SetLogLoggerLevel(slog.Level(gConfig.LogLevel))

	// Setup listener
	listener, err := net.Listen("tcp", gConfig.Host)
	if err != nil {
		slog.Error("failed to setup listener", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer listener.Close()

	slog.Info("client started and ready to accept connections", slog.String("host", listener.Addr().String()))

	// Wait for connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("failed to accept connection", slog.String("err", err.Error()))
			continue
		}

		go HandleSession(conn)
	}
}
