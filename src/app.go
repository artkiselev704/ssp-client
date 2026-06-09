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
	Attempts int      `json:"attempts"`
	Timeout  int      `json:"timeout"`
	LogLevel int      `json:"log_level"`
}

type InboundData struct {
	seqNum uint8
	data   []byte
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

func GetConnection(previousServerIdx int) (net.Conn, int, error) {
	// Check total size
	total := len(gConfig.Servers)
	if total == 0 {
		return nil, 0, fmt.Errorf("no servers available")
	}

	// Select random server
	idx := 0
	for {
		if total == 1 {
			break
		}

		idx = rand.Intn(total)
		if idx != previousServerIdx {
			break
		}
	}

	// Connect
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: time.Duration(gConfig.Timeout) * time.Second,
		},
		Config: &gTLSConfig,
	}
	conn, err := dialer.Dial("tcp", gConfig.Servers[idx])
	return conn, idx, err
}

func DoRegister(addr string, port uint16) (net.Conn, []byte, int, error) {
	serverIdx := -1

	for attempt := 0; attempt < gConfig.Attempts; attempt++ {
		var (
			tgtConn net.Conn
			err     error
		)

		// Get new connection
		tgtConn, serverIdx, err = GetConnection(serverIdx)
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

		return tgtConn, uid, serverIdx, nil
	}

	return nil, nil, 0, fmt.Errorf("attempts limit exceeded")
}

func DoExchange(srcConn net.Conn, tgtConn net.Conn, uid []byte, serverIdx int) error {
	// Session data
	var (
		srcSeqNum   uint8  = 0
		pendingData []byte = nil
	)

	// Setup source
	var (
		srcErrCh     = make(chan error, 10)
		srcInDataCh  = make(chan []byte, 1)
		srcOutDataCh = make(chan InboundData, 1)
	)
	srcCtx, srcCancel := context.WithCancel(context.Background())
	defer srcCancel()

	go func() { // source reader
		for {
			buf := make([]byte, 4096)
			n, readerErr := srcConn.Read(buf)
			if readerErr != nil {
				srcErrCh <- readerErr
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
		tgtSeqNum := uint8(0)
		for {
			select {
			case <-srcCtx.Done():
				return
			case inboundData := <-srcOutDataCh:
				if tgtSeqNum != inboundData.seqNum {
					slog.Debug(fmt.Sprintf("Warning: target sequence numbers do not match (%d != %d)", tgtSeqNum, inboundData.seqNum))
					continue
				}
				if _, writerErr := srcConn.Write(inboundData.data); writerErr != nil {
					srcErrCh <- writerErr
					return
				}
				tgtSeqNum++
			}
		}
	}()

	// Connect to the target
	needReconnect := tgtConn == nil
	for attempt := 0; attempt < gConfig.Attempts; attempt++ {
		// Reconnect
		if needReconnect {
			var err error
			if tgtConn, serverIdx, err = GetConnection(serverIdx); err != nil {
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
				if writerErr := STCPDoPush(tgtConn, srcSeqNum, pendingData, uint16(len(pendingData))); writerErr != nil {
					tgtErrCh <- writerErr
					return
				}

				// Wait for ACK
				select {
				case <-tgtCtx.Done():
					return
				case <-ackCh:
					srcSeqNum++
					pendingData = nil
				}
			}
		}()

		go func() { // target reader
			for {
				// Get opcode
				opcode, readerErr := STCPGetOpCode(tgtConn)
				if readerErr != nil {
					tgtErrCh <- readerErr
					return
				}

				switch opcode {
				case 0x03: // PUSH
					// Handle
					recTgtSeqNum, data, readerErr := STCPHandlePush(tgtConn)
					if readerErr != nil {
						tgtErrCh <- readerErr
						return
					}

					// Write
					select {
					case <-tgtCtx.Done():
						return
					case srcOutDataCh <- InboundData{recTgtSeqNum, data}:
					}

					// Confirm
					if readerErr = STCPDoPushAck(tgtConn, recTgtSeqNum); readerErr != nil {
						tgtErrCh <- readerErr
						return
					}
				case 0x04: // PUSH ACK
					// Handle
					recSrcSeqNum, readerErr := STCPHandlePushAck(tgtConn)
					if readerErr != nil {
						tgtErrCh <- readerErr
						return
					}

					// Compare sequence numbers
					if srcSeqNum != recSrcSeqNum {
						tgtErrCh <- fmt.Errorf("source sequence numbers do not match (%d != %d)", srcSeqNum, recSrcSeqNum)
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
					tgtErrCh <- fmt.Errorf("unknown opcode (%d)", opcode)
					return
				}
			}
		}()

		// Handle events
		doExit := false

		select {
		case <-tgtCtx.Done():
			doExit = true
		case err = <-srcErrCh:
			slog.Debug("DoExchange -> srcErrCh", slog.String("err", err.Error()))
			doExit = true
			STCPDoFinish(tgtConn)
		case err = <-tgtErrCh:
			slog.Debug("DoExchange -> tgtErrCh", slog.String("err", err.Error()))
			needReconnect = true
		}

		tgtCancel()
		tgtConn.Close()

		if doExit {
			return nil
		}
	}

	return fmt.Errorf("attempts limit exceeded")
}

func HandleSession(srcConn net.Conn) {
	// Handle current session
	RemoteAddr := srcConn.RemoteAddr().String()
	slog.Info("New session",
		slog.String("RemoteAddr", RemoteAddr),
		slog.Int("NumGoroutine", runtime.NumGoroutine()),
	)
	defer func() {
		slog.Info("Session finished",
			slog.String("RemoteAddr", RemoteAddr),
			slog.Int("NumGoroutine", runtime.NumGoroutine()),
		)
		srcConn.Close()
	}()

	// Do SOCKS handshake
	if err := SOCKSHandleHandshake(srcConn); err != nil {
		slog.Error("SOCKSHandleHandshake error",
			slog.String("RemoteAddr", RemoteAddr),
			slog.String("err", err.Error()),
		)
		return
	}

	// Select SOCKS method
	if err := SOCKSDoHandshakeReply(srcConn, 0x00); err != nil {
		slog.Error("SOCKSDoHandshakeReply error",
			slog.String("RemoteAddr", RemoteAddr),
			slog.String("err", err.Error()),
		)
		return
	}

	// Handle SOCKS request
	tgtAddr, tgtPort, atyp, err := SOCKSHandleRequest(srcConn)
	if err != nil {
		slog.Error("SOCKSHandleRequest error",
			slog.String("RemoteAddr", RemoteAddr),
			slog.String("err", err.Error()),
		)
		return
	}

	// Confirm SOCKS connection
	if err = SOCKSDoRequestReply(srcConn, 0x00, atyp, tgtAddr, tgtPort); err != nil {
		slog.Error("SOCKSDoRequestReply error",
			slog.String("RemoteAddr", RemoteAddr),
			slog.String("err", err.Error()),
		)
		return
	}

	// Register new session
	tgtConn, uid, serverIdx, err := DoRegister(tgtAddr, tgtPort)
	if err != nil {
		slog.Error("DoRegister error",
			slog.String("RemoteAddr", RemoteAddr),
			slog.String("err", err.Error()),
		)
		return
	}

	// Exchange
	if err = DoExchange(srcConn, tgtConn, uid, serverIdx); err != nil {
		slog.Error("DoExchange error",
			slog.String("RemoteAddr", RemoteAddr),
			slog.String("err", err.Error()),
		)
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
