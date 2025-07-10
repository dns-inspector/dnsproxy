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
	"dnsproxy/monitoring"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ecnepsnai/sdnotify"
	"github.com/quic-go/quic-go"
)

var (
	Version  = "dev"
	BuiltOn  = "unknown"
	Revision = "unknown"
)

var (
	serverConfig *tServerConfig
	logLock      = &sync.Mutex{}
	logFile      *os.File
)

var (
	listenerTLS4   net.Listener
	listenerTLS6   net.Listener
	listenerQuic4  *quic.EarlyListener
	listenerQuic6  *quic.EarlyListener
	listenerHTTPS4 net.Listener
	listenerHTTPS6 net.Listener
)

var (
	serverShouldRestart = false
	restartLock         = &sync.Mutex{}
)

func Start(configPath string) (bool, error) {
	serverConfig = mustLoadConfig(configPath)

	if f, err := os.OpenFile(serverConfig.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		logFile = f
	}

	cert, err := tls.LoadX509KeyPair(serverConfig.CertPath, serverConfig.KeyPath)
	if err != nil {
		return false, fmt.Errorf("unable to load certificate or private key: %s", err.Error())
	}

	if serverConfig.ZabbixHost != nil && monitoring.Setup(serverConfig.ServerName, *serverConfig.ZabbixHost) == nil {
		go monitoring.StartSendLoop()
	}

	listenErr := make(chan error, 1)

	go func() {
		if serverConfig.TLSPort == 0 {
			return
		}
		c := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		l, err := tls.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", serverConfig.TLSPort), c)
		if err != nil {
			listenErr <- fmt.Errorf("unable to start IPv4 TLS server: %s", err.Error())
			return
		}
		listenerTLS4 = l
		if serverConfig.Verbosity >= 3 {
			logf("main", "debug", "", "", "Start: TLS server started on: %s", l.Addr().String())
		}

		listenErr <- tlsServer(l)
	}()

	go func() {
		if serverConfig.TLSPort == 0 {
			return
		}
		c := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		l, err := tls.Listen("tcp6", fmt.Sprintf("[::]:%d", serverConfig.TLSPort), c)
		if err != nil {
			listenErr <- fmt.Errorf("unable to start IPv6 TLS server: %s", err.Error())
			return
		}
		listenerTLS4 = l
		if serverConfig.Verbosity >= 3 {
			logf("main", "debug", "", "", "Start: TLS server started on: %s", l.Addr().String())
		}

		listenErr <- tlsServer(l)
	}()

	go func() {
		port := serverConfig.QuicPort
		if port == 0 {
			port = serverConfig.TLSPort
		}
		if port == 0 {
			return
		}
		c := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"doq"},
		}

		pc, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			listenErr <- fmt.Errorf("unable to start IPv4 Quic server: %s", err.Error())
			return
		}
		qc := &quic.Transport{
			Conn: pc,
		}
		l, err := qc.ListenEarly(c, nil)
		if err != nil {
			listenErr <- fmt.Errorf("unable to start IPv4 Quic server: %s", err.Error())
			return
		}
		if serverConfig.Verbosity >= 3 {
			logf("main", "debug", "", "", "Start: Quic server started on: %s", l.Addr().String())
		}

		listenerQuic4 = l
		listenErr <- quicServer(l)
	}()

	go func() {
		port := serverConfig.QuicPort
		if port == 0 {
			port = serverConfig.TLSPort
		}
		if port == 0 {
			return
		}
		c := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"doq"},
		}

		pc, err := net.ListenPacket("udp6", fmt.Sprintf("[::]:%d", port))
		if err != nil {
			listenErr <- fmt.Errorf("unable to start IPv6 Quic server: %s", err.Error())
			return
		}
		qc := &quic.Transport{
			Conn: pc,
		}
		l, err := qc.ListenEarly(c, nil)
		if err != nil {
			listenErr <- fmt.Errorf("unable to start IPv6 Quic server: %s", err.Error())
			return
		}
		if serverConfig.Verbosity >= 3 {
			logf("main", "debug", "", "", "Start: Quic server started on: %s", l.Addr().String())
		}

		listenerQuic6 = l
		listenErr <- quicServer(l)
	}()

	go func() {
		if serverConfig.HTTPSPort == 0 {
			return
		}
		c := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}

		l, err := tls.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", serverConfig.HTTPSPort), c)
		if err != nil {
			listenErr <- fmt.Errorf("unable to start IPv4 HTTPS server: %s", err.Error())
			return
		}
		listenerHTTPS4 = l
		if serverConfig.Verbosity >= 3 {
			logf("main", "debug", "", "", "Start: HTTPS server started on: %s", l.Addr().String())
		}

		listenErr <- http.Serve(l, &httpServer{})
	}()

	go func() {
		if serverConfig.HTTPSPort == 0 {
			return
		}
		c := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}

		l, err := tls.Listen("tcp6", fmt.Sprintf("[::]:%d", serverConfig.HTTPSPort), c)
		if err != nil {
			listenErr <- fmt.Errorf("unable to start IPv6 HTTPS server: %s", err.Error())
			return
		}
		listenerHTTPS4 = l
		if serverConfig.Verbosity >= 3 {
			logf("main", "debug", "", "", "Start: HTTPS server started on: %s", l.Addr().String())
		}

		listenErr <- http.Serve(l, &httpServer{})
	}()

	if serverConfig.Verbosity >= 2 {
		logf("main", "info", "", "", "Server started")
	}

	sdnotify.Ready()

	for {
		select {
		case err := <-listenErr:
			restartLock.Lock()
			shouldRestart := serverShouldRestart
			restartLock.Unlock()
			return shouldRestart, err
		case <-time.After(1 * time.Second):
			sdnotify.Watchdog()
		}
	}
}

func Stop(restart bool) {
	if serverConfig.Verbosity >= 2 {
		logf("main", "info", "", "", "Server stopped")
	}

	stop(restart)
}

func stop(restart bool) {
	restartLock.Lock()
	serverShouldRestart = restart
	if restart {
		sdnotify.Reloading()
	} else {
		sdnotify.Stopping()
	}
	restartLock.Unlock()

	if logFile != nil {
		logLock.Lock()
		logFile.Sync()
		logFile.Close()
		logFile = nil
		logLock.Unlock()
	}
	if listenerTLS4 != nil {
		listenerTLS4.Close()
		listenerTLS4 = nil
	}
	if listenerTLS6 != nil {
		listenerTLS6.Close()
		listenerTLS6 = nil
	}
	if listenerQuic4 != nil {
		listenerQuic4.Close()
		listenerQuic4 = nil
	}
	if listenerQuic6 != nil {
		listenerQuic6.Close()
		listenerQuic6 = nil
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
