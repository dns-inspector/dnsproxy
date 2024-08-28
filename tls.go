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
	"encoding/binary"
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

func handleTlsConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			conn.Close()
			logf("tls", "error", "", "", "handleTlsConn: recovered from panic: %s", r)
		}
	}()

	logf("tls", "info", conn.RemoteAddr().String(), "", "connect")
	defer conn.Close()

	rawSize := make([]byte, 2)

	if _, err := conn.Read(rawSize); err != nil {
		logf("tls", "warn", conn.RemoteAddr().String(), "", "error reading message: %s", err.Error())
		return
	}
	size := binary.BigEndian.Uint16(rawSize)
	if size > 4096 {
		logf("tls", "warn", conn.RemoteAddr().String(), "", "request too large: %d", size)
		conn.Write([]byte("request too large"))
		return
	}

	message := make([]byte, size)
	read, err := conn.Read(message)
	if err != nil {
		logf("tls", "warn", conn.RemoteAddr().String(), "", "error reading message: %s", err.Error())
		return
	}
	if read != int(size) {
		logf("tls", "warn", conn.RemoteAddr().String(), "", "invalid message size")
		conn.Write([]byte("invalid message size"))
		return
	}

	message = append(rawSize, message...)

	reply, err := proxyDnsMessage(message)
	if err != nil {
		logf("tls", "error", conn.RemoteAddr().String(), "", "error proxying message: %s", err.Error())
		return
	}

	conn.Write(reply)
}
