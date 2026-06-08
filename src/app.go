package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

func LoadConfig() error {
	// Read config.json
	file, err := os.Open("config.json")
	if err != nil {
		return err
	}
	defer file.Close()

	// Decode json
	if err := json.NewDecoder(file).Decode(&gConfig); err != nil {
		return err
	}

	// Read certificate
	cert, err := os.ReadFile("cert.crt")
	if err != nil {
		return err
	}

	// Configure TLS
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

func DoRegister(addr string, port uint16) (net.Conn, []byte, error) {
	for i := 0; i < gConfig.Retries; i++ {
		// Get new connection
		tgtConn, err := GetConnection()
		if err != nil {
			slog.Debug("DoRegister -> GetConnection error", slog.String("err", err.Error()))
			continue
		}

		// Send register request
		if err := STCPDoRegister(tgtConn, addr, port); err != nil {
			slog.Debug("DoRegister -> STCPDoRegister error", slog.String("err", err.Error()))
			tgtConn.Close()
			continue
		}

		// Read register response
		uid, err := STCPHandleRegisterReply(tgtConn)
		if err != nil {
			slog.Debug("DoRegister -> STCPHandleRegisterReply error", slog.String("err", err.Error()))
			tgtConn.Close()
			continue
		}

		return tgtConn, uid, nil
	}

	return nil, nil, fmt.Errorf("retries limit exceeded")
}

func DoExchange(srcConn net.Conn, tgtConn net.Conn, uid []byte) error {
	// Session data
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

	go func() { // source reader
		for {
			buf := make([]byte, 4096)
			n, err := srcConn.Read(buf)
			if err != nil {
				srcErrCh <- err
				return
			}
			if n > 0 {
				select {
				case <-srcCtx.Done():
					return
				case srcInDataCh <- buf[:n]:
				}
			}
		}
	}()

	go func() { // source writer
		for {
			select {
			case <-srcCtx.Done():
				return
			case data := <-srcOutDataCh:
				if _, err := srcConn.Write(data); err != nil {
					srcErrCh <- err
					return
				}
			}
		}
	}()

	// Connect to the target
	needReconnect := tgtConn == nil
	for attempt := 0; attempt < gConfig.Retries; attempt++ {
		// Reconnect
		if needReconnect {
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
			needReconnect = true
			continue
		}

		// Check control reply
		reply, err := STCPHandleControlReply(tgtConn)
		if err != nil {
			slog.Debug("DoExchange -> STCPHandleControlReply error", slog.String("err", err.Error()))
			tgtConn.Close()
			needReconnect = true
			continue
		}

		// If reply != 0x01, finish current session
		if reply != 0x01 {
			slog.Debug("DoExchange -> Failed to take control", slog.Int("reply", int(reply)))
			return nil
		}

		// Reset attempts
		attempt = 0

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
					case <-tgtCtx.Done():
						return
					case pendingData = <-srcInDataCh:
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
				// Get opcode
				opcode, err := STCPGetOpCode(tgtConn)
				if err != nil {
					tgtErrCh <- err
					return
				}

				switch opcode {
				case 0x03: // PUSH
					// Handle
					inSequenceNum, data, err := STCPHandlePush(tgtConn)
					if err != nil {
						tgtErrCh <- err
						return
					}

					// Write
					select {
					case <-tgtCtx.Done():
						return
					case srcOutDataCh <- data:
					}

					// Confirm
					if err := STCPDoPushAck(tgtConn, inSequenceNum); err != nil {
						tgtErrCh <- err
						return
					}
				case 0x04: // PUSH ACK
					// Handle
					inSequenceNum, err := STCPHandlePushAck(tgtConn)
					if err != nil {
						tgtErrCh <- err
						return
					}

					// Compare sequence numbers
					if sequenceNum != inSequenceNum {
						tgtErrCh <- fmt.Errorf("sequence numbers do not match (%d != %d)", sequenceNum, inSequenceNum)
						return
					}

					// Confirm
					select {
					case <-tgtCtx.Done():
						return
					case ackCh <- struct{}{}:
					}
				case 0x05: // FINISH
					srcCancel()
					return
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
			STCPDoFinish(tgtConn)
		case err := <-tgtErrCh:
			slog.Debug("DoExchange -> tgtErrCh", slog.String("err", err.Error()))
		}

		tgtCancel()
		tgtConn.Close()
		needReconnect = true

		if doExit {
			return nil
		}
	}

	return fmt.Errorf("retries limit exceeded")
}

func HandleSession(srcConn net.Conn) {
	// Display info
	RemoteAddr := srcConn.RemoteAddr().String()
	slog.Info("HandleSession -> NEW",
		slog.String("RemoteAddr", RemoteAddr),
		slog.Int("NumGoroutine", runtime.NumGoroutine()),
	)
	defer func() {
		slog.Info("HandleSession -> END",
			slog.String("RemoteAddr", RemoteAddr),
			slog.Int("NumGoroutine", runtime.NumGoroutine()),
		)
	}()

	// Do SOCKS handshake
	if err := SOCKSHandleHandshake(srcConn); err != nil {
		slog.Error("SOCKSHandleHandshake error", slog.String("err", err.Error()))
		return
	}

	// Select SOCKS method
	if err := SOCKSDoHandshakeReply(srcConn, 0x00); err != nil {
		slog.Error("SOCKSDoHandshakeReply error", slog.String("err", err.Error()))
		return
	}

	// Handle SOCKS request
	tgtAddr, tgtPort, atyp, err := SOCKSHandleRequest(srcConn)
	if err != nil {
		slog.Error("SOCKSHandleRequest error", slog.String("err", err.Error()))
		return
	}

	// Confirm SOCKS connection
	if err := SOCKSDoRequestReply(srcConn, 0x00, atyp, tgtAddr, tgtPort); err != nil {
		slog.Error("SOCKSDoRequestReply error", slog.String("err", err.Error()))
		return
	}

	// Register new session
	tgtConn, uid, err := DoRegister(tgtAddr, tgtPort)
	if err != nil {
		slog.Error("DoRegister error", slog.String("err", err.Error()))
		return
	}

	// Exchange
	if err = DoExchange(srcConn, tgtConn, uid); err != nil {
		slog.Error("DoExchange error", slog.String("err", err.Error()))
		return
	}
}

func main() {
	// Load config
	err := LoadConfig()
	if err != nil {
		slog.Error("Failed to load config", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Set logging level
	slog.SetLogLoggerLevel(slog.Level(gConfig.LogLevel))

	// Setup listener
	listener, err := net.Listen("tcp", gConfig.Host)
	if err != nil {
		slog.Error("Failed to setup listener", slog.String("err", err.Error()))
		os.Exit(1)
	}
	defer listener.Close()

	// Wait for connections
	slog.Info("Client started and ready to accept connections", slog.String("host", listener.Addr().String()))
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("Failed to accept connection", slog.String("err", err.Error()))
			continue
		}

		go HandleSession(conn)
	}
}
