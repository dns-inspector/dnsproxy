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
	"dnsproxy/monitoring"
	"encoding/binary"
	"io"

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

	rawSize := make([]byte, 2)

	if _, err := rw.Read(rawSize); err != nil {
		if serverConfig.Verbosity >= 2 {
			logf("quic", "warn", conn.RemoteAddr().String(), "", "error reading message length: %s", err.Error())
		}
		monitoring.RecordQueryDotError()
		return
	}
	size := binary.BigEndian.Uint16(rawSize)
	if size > 4096 {
		if serverConfig.Verbosity >= 2 {
			logf("quic", "warn", conn.RemoteAddr().String(), "", "request too large: %d", size)
		}
		rw.Write([]byte("request too large"))
		monitoring.RecordQueryDotError()
		return
	}

	message := make([]byte, size)
	read, err := rw.Read(message)
	if err != nil && err != io.EOF {
		if serverConfig.Verbosity >= 2 {
			logf("quic", "warn", conn.RemoteAddr().String(), "", "error reading message: %s", err.Error())
		}
		monitoring.RecordQueryDotError()
		return
	}
	if read != int(size) {
		if serverConfig.Verbosity >= 2 {
			logf("quic", "warn", conn.RemoteAddr().String(), "", "invalid message size")
		}
		rw.Write([]byte("invalid message size"))
		monitoring.RecordQueryDotError()
		return
	}

	message = append(rawSize, message...)

	reply, err := proxyDnsMessage(message)
	if err != nil {
		if serverConfig.Verbosity >= 1 {
			logf("quic", "error", conn.RemoteAddr().String(), "", "error proxying message: %s", err.Error())
		}
		monitoring.RecordQueryDotError()
		return
	}

	if serverConfig.Verbosity >= 3 {
		logf("quic", "trace", conn.RemoteAddr().String(), "", "message: %02x reply: %02x", message, reply)
	}

	logf("quic", "stats", "", "", "message proxied")
	monitoring.RecordQueryDotForward()
	rw.Write(reply)
}
