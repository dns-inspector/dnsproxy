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
	"sync"
	"time"

	"github.com/ecnepsnai/logtic"
	"github.com/ecnepsnai/sdnotify"
	"github.com/quic-go/quic-go"
)

var (
	Version  = "dev"
	BuiltOn  = "unknown"
	Revision = "unknown"
)

var serverConfig *tServerConfig
var log = logtic.Log.Connect("dnsproxy")

var (
	listenerTLS4   net.Listener
	listenerTLS6   net.Listener
	listenerQuic4  *quic.EarlyListener
	listenerQuic6  *quic.EarlyListener
	listenerHTTPS4 net.Listener
	listenerHTTPS6 net.Listener
	listenerHTTP4  net.Listener
	listenerHTTP6  net.Listener
)

var (
	serverShouldRestart = false
	restartLock         = &sync.Mutex{}
)

func Start(configPath string) (bool, error) {
	serverConfig = mustLoadConfig(configPath)

	setupLog()

	cert, err := tls.LoadX509KeyPair(serverConfig.CertPath, serverConfig.KeyPath)
	if err != nil {
		return false, fmt.Errorf("unable to load certificate or private key: %s", err.Error())
	}

	if serverConfig.ZabbixHost != nil && monitoring.Setup(serverConfig.ServerName, *serverConfig.ZabbixHost) == nil {
		go monitoring.StartSendLoop()
	}

	listenErr := make(chan error, 1)

	startTlsServer(listenErr, cert)
	startQuicServer(listenErr, cert)
	startHttpsServer(listenErr, cert)
	startHttpServer(listenErr)

	log.PInfo("Server started", map[string]any{
		"server_name": serverConfig.ServerName,
		"version":     Version,
	})

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
	log.Warn("Server stopping")
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

	logtic.Log.Close()
	if requestLog != nil {
		requestLog.Close()
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
	if listenerHTTP4 != nil {
		listenerHTTP4.Close()
		listenerHTTP4 = nil
	}
	if listenerHTTP6 != nil {
		listenerHTTP6.Close()
		listenerHTTP6 = nil
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
