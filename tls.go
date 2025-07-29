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
)

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
}

func handleTlsConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			monitoring.RecordPanicRecover()
			conn.Close()
			if serverConfig.Verbosity >= 1 {
				logf("tls", "error", "", "", "handleTlsConn: recovered from panic: %s", r)
			}
		}
	}()

	if serverConfig.Verbosity >= 3 {
		logf("tls", "info", conn.RemoteAddr().String(), "", "connect")
	}
	defer conn.Close()

	rawSize := make([]byte, 2)

	if _, err := conn.Read(rawSize); err != nil {
		if serverConfig.Verbosity >= 2 {
			logf("tls", "warn", conn.RemoteAddr().String(), "", "error reading message: %s", err.Error())
		}
		monitoring.RecordQueryDotError()
		return
	}
	size := binary.BigEndian.Uint16(rawSize)
	if size > 4096 {
		if serverConfig.Verbosity >= 2 {
			logf("tls", "warn", conn.RemoteAddr().String(), "", "request too large: %d", size)
		}
		conn.Write([]byte("request too large"))
		monitoring.RecordQueryDotError()
		return
	}

	message := make([]byte, size)
	read, err := conn.Read(message)
	if err != nil {
		if serverConfig.Verbosity >= 2 {
			logf("tls", "warn", conn.RemoteAddr().String(), "", "error reading message: %s", err.Error())
		}
		monitoring.RecordQueryDotError()
		return
	}
	if read != int(size) {
		if serverConfig.Verbosity >= 2 {
			logf("tls", "warn", conn.RemoteAddr().String(), "", "invalid message size")
		}
		conn.Write([]byte("invalid message size"))
		monitoring.RecordQueryDotError()
		return
	}

	message = append(rawSize, message...)

	reply, err := proxyDnsMessage(message)
	if err != nil {
		if serverConfig.Verbosity >= 1 {
			logf("tls", "error", conn.RemoteAddr().String(), "", "error proxying message: %s", err.Error())
		}
		monitoring.RecordQueryDotError()
		return
	}

	if serverConfig.Verbosity >= 3 {
		logf("tls", "trace", conn.RemoteAddr().String(), "", "message: %02x reply: %02x", message, reply)
	}

	logf("tls", "stats", "", "", "message proxied")
	monitoring.RecordQueryDotForward()
	conn.Write(reply)
}
