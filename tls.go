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
	"fmt"
	"net"
	"runtime/debug"

	"github.com/ecnepsnai/logtic"
)

var tlsLog = logtic.Log.Connect("tls")

func tlsServer(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go handleTlsConn(conn)
	}
}

func startTlsServer(listenErr chan error, cert tls.Certificate) {
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
		tlsLog.Debug("Start: TLS server started on: %s", l.Addr().String())

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
		tlsLog.Debug("Start: TLS server started on: %s", l.Addr().String())

		listenErr <- tlsServer(l)
	}()
}

func handleTlsConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			monitoring.RecordPanicRecover()
			conn.Close()
			tlsLog.PError("TLS server paniced", map[string]any{
				"error": fmt.Sprintf("%s", r),
				"stack": fmt.Sprintf("%s", debug.Stack()),
			})
		}
	}()

	defer conn.Close()

	if err := proxyDNSMessageWithLength(tlsLog, "tls", conn.RemoteAddr().String(), conn); err != nil {
		monitoring.RecordQueryDotError()
		return
	}
	monitoring.RecordQueryDotForward()
}
