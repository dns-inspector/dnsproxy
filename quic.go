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
	"context"
	"crypto/tls"
	"dnsproxy/monitoring"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

func quicServer(l *quic.EarlyListener) error {
	for {
		conn, err := l.Accept(context.Background())
		if err != nil {
			if err == quic.ErrServerClosed {
				return err
			}

			if serverConfig.Verbosity >= 1 {
				logf("quic", "error", "", "", "quicServer: error accepting incomming connection: %s", err.Error())
			}
			continue
		}
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			if serverConfig.Verbosity >= 1 {
				logf("quic", "error", "", "", "quicServer: error accepting incomming connection: %s", err.Error())
			}
			continue
		}
		go handleQuicConn(conn, stream)
	}
}

func startQuicServer(listenErr chan error, cert tls.Certificate) {
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
}

func handleQuicConn(conn *quic.Conn, rw *quic.Stream) {
	defer func() {
		if r := recover(); r != nil {
			monitoring.RecordPanicRecover()
			rw.Close()
			if serverConfig.Verbosity >= 1 {
				logf("quic", "error", "", "", "handleQuicConn: recovered from panic: %s", r)
			}
		}
	}()
	defer rw.Close()

	if serverConfig.Verbosity >= 3 {
		logf("quic", "info", conn.RemoteAddr().String(), "", "connect")
	}

	if err := proxyDNSMessageWithLength("quic", conn.RemoteAddr().String(), rw); err != nil {
		monitoring.RecordQueryDotError()
		return
	}
	monitoring.RecordQueryDotForward()
}
