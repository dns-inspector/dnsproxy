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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
)

type httpServer struct{}

func (s *httpServer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logf("https", "error", "", "", "ServeHTTP: recovered from panic: %s", r)
		}
	}()

	rw.Header().Add("X-Powered-By", "-")
	rw.Header().Add("Server", "-")

	useragent := r.Header.Get("User-Agent")
	logf("https", "info", r.RemoteAddr, useragent, "connect")

	defer r.Body.Close()

	if r.URL.Path == "/dns-query" {
		var message []byte
		if r.Method == "GET" {
			encodedMessage := r.URL.Query().Get("dns")
			if encodedMessage == "" {
				logf("https", "info", r.RemoteAddr, useragent, "missing dns query in url")
				rw.WriteHeader(400)
				rw.Write([]byte("missing dns query in url"))
				return
			}
			m, err := base64.RawURLEncoding.DecodeString(encodedMessage)
			if err != nil {
				logf("https", "info", r.RemoteAddr, useragent, "invalid base64 data in dns query")
				rw.WriteHeader(400)
				rw.Write([]byte("invalid base64 value in dns query"))
				return
			}
			message = m
		} else if r.Method == "POST" {
			if r.ContentLength > 4096 {
				logf("https", "info", r.RemoteAddr, useragent, "message too large")
				rw.WriteHeader(400)
				rw.Write([]byte("message too large"))
				return
			}
			m, err := io.ReadAll(r.Body)
			if err != nil {
				rw.WriteHeader(500)
				return
			}
			message = m
		} else {
			rw.WriteHeader(405)
			return
		}

		length := make([]byte, 2)
		binary.BigEndian.PutUint16(length, uint16(len(message)))

		message = append(length, message...)
		reply, err := proxyDnsMessage(message)
		if err != nil {
			logf("https", "error", r.RemoteAddr, useragent, "error proxying dns message: %s", err.Error())
			rw.WriteHeader(500)
			rw.Write([]byte("internal server error"))
			return
		}
		rw.Header().Set("Content-Type", "application/dns-message")
		rw.Header().Set("Content-Length", fmt.Sprintf("%d", len(reply[2:])))
		rw.WriteHeader(200)
		rw.Write(reply[2:])
		return
	} else if r.URL.Path == "/" {
		rw.Header().Add("Location", "https://dnsinspector.com/dns.html")
		rw.WriteHeader(302)
		return
	}

	logf("https", "warn", r.RemoteAddr, useragent, "unknown url: %s", r.URL.String())
	rw.WriteHeader(404)
}
