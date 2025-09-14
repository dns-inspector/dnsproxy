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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/ecnepsnai/logtic"
)

func startHttpsServer(listenErr chan error, cert tls.Certificate) {
	source := logtic.Log.Connect("https")

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
		log.Debug("HTTPS server started on: %s", l.Addr().String())

		listenErr <- http.Serve(l, &httpsServer{source})
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
		log.Debug("HTTPS server started on: %s", l.Addr().String())

		listenErr <- http.Serve(l, &httpsServer{source})
	}()
}

type httpsServer struct {
	log *logtic.Source
}

func (s *httpsServer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			monitoring.RecordPanicRecover()
			s.log.PError("HTTPS server paniced", map[string]any{
				"error": fmt.Sprintf("%s", r),
				"stack": fmt.Sprintf("%s", debug.Stack()),
			})
		}
	}()

	rw.Header().Add("Date", time.Now().UTC().Format(time.RFC1123))
	rw.Header().Add("X-Powered-By", "-")
	rw.Header().Add("Server", "-")

	useragent := r.Header.Get("User-Agent")
	// Reject requests without a user agent
	if useragent == "" {
		rw.WriteHeader(400)
		rw.Write([]byte("a user agent is required"))
		s.log.PDebug("Request finished", map[string]any{
			"method":      r.Method,
			"uri_stem":    r.URL.Path,
			"status_code": 400,
			"user_agent":  r.UserAgent(),
		})
		return
	}

	defer r.Body.Close()

	if r.URL.Path == "/" && serverConfig.HTTPRedirect != "" {
		rw.Header().Add("Location", serverConfig.HTTPRedirect)
		rw.WriteHeader(302)
		s.log.PDebug("Request finished", map[string]any{
			"method":      r.Method,
			"uri_stem":    r.URL.Path,
			"status_code": 302,
			"user_agent":  r.UserAgent(),
		})
		return
	}

	if r.URL.Path != "/dns-query" {
		rw.WriteHeader(404)
		s.log.PDebug("Request finished", map[string]any{
			"method":      r.Method,
			"uri_stem":    r.URL.Path,
			"status_code": 404,
			"user_agent":  r.UserAgent(),
		})
		return
	}

	if r.Method != "GET" && r.Method != "POST" {
		rw.WriteHeader(405)
		s.log.PDebug("Request finished", map[string]any{
			"method":      r.Method,
			"uri_stem":    r.URL.Path,
			"status_code": 405,
			"user_agent":  r.UserAgent(),
		})
		return
	}

	var message []byte
	if r.Method == "GET" {
		encodedMessage := r.URL.Query().Get("dns")
		if encodedMessage == "" {
			monitoring.RecordQueryDohError()
			rw.WriteHeader(400)
			rw.Write([]byte("missing dns query in url"))
			s.log.PDebug("Request finished", map[string]any{
				"method":      r.Method,
				"uri_stem":    r.URL.Path,
				"status_code": 400,
				"user_agent":  r.UserAgent(),
				"error":       "missing dns query param in url",
			})
			return
		}
		m, err := base64.RawURLEncoding.DecodeString(encodedMessage)
		if err != nil {
			monitoring.RecordQueryDohError()
			rw.WriteHeader(400)
			rw.Write([]byte("invalid base64 value in dns query"))
			s.log.PDebug("Request finished", map[string]any{
				"method":      r.Method,
				"uri_stem":    r.URL.Path,
				"status_code": 400,
				"user_agent":  r.UserAgent(),
				"error":       "invalid base64 data in dns query param",
			})
			return
		}
		if len(m) <= 12 {
			monitoring.RecordQueryDohError()
			rw.WriteHeader(400)
			rw.Write([]byte("invalid base64 value in dns query"))
			s.log.PDebug("Request finished", map[string]any{
				"method":      r.Method,
				"uri_stem":    r.URL.Path,
				"status_code": 400,
				"user_agent":  r.UserAgent(),
				"error":       "invalid base64 data in dns query param",
			})
			return
		}
		message = m
	} else if r.Method == "POST" {
		if r.ContentLength > 4096 {
			monitoring.RecordQueryDohError()
			rw.WriteHeader(400)
			rw.Write([]byte("message too large"))
			s.log.PDebug("Request finished", map[string]any{
				"method":      r.Method,
				"uri_stem":    r.URL.Path,
				"status_code": 400,
				"user_agent":  r.UserAgent(),
				"error":       "message too large",
			})
			return
		}
		m, err := io.ReadAll(r.Body)
		if err != nil {
			monitoring.RecordQueryDohError()
			rw.WriteHeader(400)
			s.log.PDebug("Request finished", map[string]any{
				"method":      r.Method,
				"uri_stem":    r.URL.Path,
				"status_code": 400,
				"user_agent":  r.UserAgent(),
				"error":       err.Error(),
			})
			return
		}
		message = m
	} else {
		monitoring.RecordQueryDohError()
		rw.WriteHeader(405)
		s.log.PDebug("Request finished", map[string]any{
			"method":      r.Method,
			"uri_stem":    r.URL.Path,
			"status_code": 405,
			"user_agent":  r.UserAgent(),
		})
		return
	}

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(message)))

	message = append(length, message...)

	reply := processControlQuery(r.RemoteAddr, message)
	if reply == nil {
		var err error
		reply, err = proxyDnsMessage(message)
		if err != nil {
			log.PError("Error proxying DNS message", map[string]any{
				"proto":   "https",
				"from_ip": r.RemoteAddr,
				"error":   err.Error(),
			})
			monitoring.RecordQueryDohError()
			rw.WriteHeader(500)
			rw.Write([]byte("internal server error"))
			s.log.PDebug("Request finished", map[string]any{
				"method":      r.Method,
				"uri_stem":    r.URL.Path,
				"status_code": 400,
				"user_agent":  r.UserAgent(),
				"error":       err.Error(),
			})
			return
		}
	}

	if requestLog != nil {
		requestLog.Record("https", r.RemoteAddr, message, reply)
	}
	monitoring.RecordQueryDohForward()
	rw.Header().Set("Content-Type", "application/dns-message")
	rw.Header().Set("Content-Length", fmt.Sprintf("%d", len(reply[2:])))
	rw.WriteHeader(200)
	rw.Write(reply[2:]) // proxyDnsMessage includes the length, skip that in DoH
	s.log.PDebug("Request finished", map[string]any{
		"method":      r.Method,
		"uri_stem":    r.URL.Path,
		"status_code": 200,
		"user_agent":  r.UserAgent(),
	})
}
