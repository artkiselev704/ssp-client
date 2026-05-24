package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
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
	defer func() {
		CloseFile(file)
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

func HandleSession(srcConn net.Conn) {
	// Handle current session
	slog.Info("new session",
		slog.String("srcAddr", srcConn.RemoteAddr().String()),
	)
	defer func() {
		CloseConnection(srcConn)
		slog.Debug("session closed", slog.Int("goroutine_num", runtime.NumGoroutine()))
	}()

	// Handle SOCKS handshake
	err := SOCKSHandleHandshake(srcConn)
	if err != nil {
		slog.Error("SOCKSHandleHandshake error", slog.String("err", err.Error()))
		return
	}

	// Select SOCKS method
	err = SOCKSDoHandshakeReply(srcConn, 0x00)
	if err != nil {
		slog.Error("SOCKSDoHandshakeReply error", slog.String("err", err.Error()))
		return
	}

	// Handle SOCKS request
	tgtAddr, tgtPort, err := SOCKSHandleRequest(srcConn)
	if err != nil {
		slog.Error("SOCKSHandleRequest error", slog.String("err", err.Error()))
		return
	}

	// Try to connect to the server
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: time.Duration(gConfig.Timeout) * time.Second,
		},
		Config: &gTLSConfig,
	}
	srvConn, err := dialer.Dial("tcp", gConfig.Servers[0])
	if err != nil {
		slog.Error("failed to connect to the server", slog.String("err", err.Error()))
		return
	}

	// Register session
	err = STCPDoRegister(srvConn, tgtAddr, tgtPort)
	if err != nil {
		slog.Error("failed to register", slog.String("err", err.Error()))
		CloseConnection(srvConn)
		return
	}

	// Fetch UID from the server
	uid, err := STCPHandleRegisterReply(srvConn)
	if err != nil {
		slog.Error("failed to handle register reply", slog.String("err", err.Error()))
		CloseConnection(srvConn)
		return
	}

	// Confirm SOCKS connection
	err = SOCKSDoRequestReply(srcConn, 0x00)
	if err != nil {
		slog.Error("SOCKSDoRequestReply error", slog.String("err", err.Error()))
		CloseConnection(srvConn)
		return
	}

	// Try to control session by UID
	err = STCPDoControl(srvConn, uid)
	if err != nil {
		slog.Error("STCPDoControl error", slog.String("err", err.Error()))
		CloseConnection(srvConn)
		return
	}

	// Check server response
	ok, err := STCPHandleControlReply(srvConn)
	if err != nil {
		slog.Error("STCPHandleControlReply error", slog.String("err", err.Error()))
		CloseConnection(srvConn)
		return
	}

	if !ok {
		slog.Error("server rejected control")
		CloseConnection(srvConn)
		return
	}

	slog.Info("passed")
	CloseConnection(srvConn)
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
	defer func() {
		err = listener.Close()
		if err != nil {
			slog.Warn("failed to close listener", slog.String("err", err.Error()))
		}
	}()

	slog.Info("client started and ready to accept connections", slog.String("host", listener.Addr().String()))

	// Wait for connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("failed to accept connection", slog.String("err", err.Error()))
		} else {
			go HandleSession(conn)
		}
	}
}
