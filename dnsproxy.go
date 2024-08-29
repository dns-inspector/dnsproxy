/*
DNSProxy
Copyright (C) 2024 Ian Spence

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package dnsproxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	Version  = "dev"
	BuiltOn  = "unknown"
	Revision = "unknown"
)

var (
	serverConfig   *tServerConfig
	logLock        = &sync.Mutex{}
	logFile        *os.File
	listenerTLS4   net.Listener
	listenerTLS6   net.Listener
	listenerHTTPS4 net.Listener
	listenerHTTPS6 net.Listener
)

func Start(configPath string) {
	serverConfig = mustLoadConfig(configPath)

	if f, err := os.OpenFile(serverConfig.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		logFile = f
	}

	cert, err := tls.LoadX509KeyPair(serverConfig.CertPath, serverConfig.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading certificate or private key: %s\n", err.Error())
		os.Exit(1)
	}

	c := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	go func() {
		l, err := tls.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", serverConfig.TLSPort), c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting IPv4 TLS server: %s\n", err.Error())
		}
		listenerTLS4 = l

		tlsServer(l)
	}()

	go func() {
		l, err := tls.Listen("tcp6", fmt.Sprintf("[::]:%d", serverConfig.TLSPort), c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting IPv6 TLS server: %s\n", err.Error())
		}
		listenerTLS6 = l

		tlsServer(l)
	}()

	go func() {
		l, err := tls.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", serverConfig.HTTPSPort), c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting IPv4 HTTPS server: %s\n", err.Error())
		}
		listenerHTTPS4 = l

		if err := http.Serve(l, &httpServer{}); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting IPv4 HTTPS server: %s\n", err.Error())
		}
	}()

	go func() {
		l, err := tls.Listen("tcp6", fmt.Sprintf("[::]:%d", serverConfig.HTTPSPort), c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error starting IPv6 HTTPS server: %s\n", err.Error())
		}
		listenerHTTPS6 = l

		if err := http.Serve(l, &httpServer{}); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting IPv6 HTTPS server: %s\n", err.Error())
		}
	}()

	if serverConfig.Verbosity >= 2 {
		logf("main", "info", "", "", "Server started")
	}
	select {}
}

func Stop() {
	if serverConfig.Verbosity >= 2 {
		logf("main", "info", "", "", "Server stopped")
	}

	if logFile != nil {
		logLock.Lock()
		logFile.Sync()
		logFile.Close()
		logFile = nil
	}
	if listenerTLS4 != nil {
		listenerTLS4.Close()
		listenerTLS4 = nil
	}
	if listenerTLS6 != nil {
		listenerTLS6.Close()
		listenerTLS6 = nil
	}
	if listenerHTTPS4 != nil {
		listenerHTTPS4.Close()
		listenerHTTPS4 = nil
	}
	if listenerHTTPS6 != nil {
		listenerHTTPS6.Close()
		listenerHTTPS6 = nil
	}
}

func RotateLog() {
	if logFile == nil {
		return
	}

	logLock.Lock()
	defer logLock.Unlock()

	logFile.Sync()
	logFile.Close()
	logFile = nil

	os.Rename(serverConfig.LogPath, fmt.Sprintf("%s.%s", serverConfig.LogPath, time.Now().AddDate(0, 0, -1).Format("2006-01-02")))

	if f, err := os.OpenFile(serverConfig.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		logFile = f
	}
}

// Proxy the given DNS message to the server.
// The message MUST include a 2-byte big-endian length at the start.
func proxyDnsMessage(message []byte) ([]byte, error) {
	out, err := net.Dial("tcp", serverConfig.DNSServerAddr)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	if _, err := out.Write(message); err != nil {
		return nil, err
	}

	rawSize := make([]byte, 2)
	if _, err := out.Read(rawSize); err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint16(rawSize)

	replyData := make([]byte, int(size))
	if _, err := out.Read(replyData); err != nil {
		return nil, err
	}

	return append(rawSize, replyData...), nil
}

func logf(proto, level, ip, useragent, format string, args ...any) {
	var message string
	if len(args) > 0 {
		message = fmt.Sprintf(format, args...)
	} else {
		message = format
	}

	line := []byte(fmt.Sprintf("%s,%s,%s,%s,%s,%s\n", time.Now().UTC().Format("2006-01-02T15:04:05-0700"), level, proto, ip, csvEscape(useragent), csvEscape(message)))
	os.Stdout.Write(line)
	if logFile != nil {
		logLock.Lock()
		logFile.Write(line)
		logLock.Unlock()
	}
}

func csvEscape(in string) string {
	if in != "" && strings.ContainsAny(in, ",\"\n") {
		in = strings.ReplaceAll(in, ",", "__COMMA__")
		in = strings.ReplaceAll(in, "\"", "__QUOTE__")
		in = strings.ReplaceAll(in, "\n", "__NEWLINE__")
	}

	return in
}
