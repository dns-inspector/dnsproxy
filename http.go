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
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func startHttpServer(listenErr chan error) {
	go func() {
		if serverConfig.HTTPPort == 0 {
			return
		}

		l, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", serverConfig.HTTPPort))
		if err != nil {
			listenErr <- fmt.Errorf("unable to start IPv4 HTTP server: %s", err.Error())
			return
		}
		listenerHTTP4 = l
		if serverConfig.Verbosity >= 3 {
			logf("main", "debug", "", "", "Start: HTTP server started on: %s", l.Addr().String())
		}

		listenErr <- http.Serve(l, &httpServer{})
	}()

	go func() {
		if serverConfig.HTTPPort == 0 {
			return
		}

		l, err := net.Listen("tcp6", fmt.Sprintf("[::]:%d", serverConfig.HTTPPort))
		if err != nil {
			listenErr <- fmt.Errorf("unable to start IPv6 HTTP server: %s", err.Error())
			return
		}
		listenerHTTP4 = l
		if serverConfig.Verbosity >= 3 {
			logf("main", "debug", "", "", "Start: HTTP server started on: %s", l.Addr().String())
		}

		listenErr <- http.Serve(l, &httpServer{})
	}()
}

type httpServer struct{}

func (s *httpServer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if serverConfig.WellKnownPath == nil {
		rw.WriteHeader(404)
		return
	}

	useragent := r.Header.Get("User-Agent")
	// Reject requests without a user agent
	if useragent == "" {
		rw.WriteHeader(400)
		rw.Write([]byte("a user agent is required"))
		return
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		rw.WriteHeader(405)
		return
	}

	urlPath := sanitizePath(r.URL.Path)

	if !strings.HasPrefix(urlPath, "/.well-known/") {
		if serverConfig.Verbosity >= 3 {
			logf("http", "trace", r.RemoteAddr, useragent, "%s %s 404", r.Method, urlPath)
		}
		rw.WriteHeader(404)
		return
	}

	localPath := path.Join(*serverConfig.WellKnownPath, urlPath[13:])

	f, err := os.Open(localPath)
	if err != nil {
		if serverConfig.Verbosity >= 3 {
			logf("http", "trace", r.RemoteAddr, useragent, "%s %s 404", r.Method, urlPath)
		}
		rw.WriteHeader(404)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		if serverConfig.Verbosity >= 3 {
			logf("http", "trace", r.RemoteAddr, useragent, "%s %s 404", r.Method, urlPath)
		}
		rw.WriteHeader(404)
		return
	}

	contentType := mime.TypeByExtension(filepath.Ext(info.Name()))
	contentLength := fmt.Sprintf("%d", info.Size())
	rw.Header().Set("Content-Type", contentType)
	rw.Header().Set("Content-Length", contentLength)
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(200)
	if serverConfig.Verbosity >= 3 {
		logf("http", "trace", r.RemoteAddr, useragent, "%s %s 200", r.Method, urlPath)
	}
	if r.Method == "HEAD" {
		return
	}
	io.Copy(rw, f)
}

// sanitizePath will remove unsafe characters and sequences from a URL path
func sanitizePath(urlPath string) string {
	urlPath = strings.ReplaceAll(urlPath, "../", "")
	bannedChars := `~,;'"?#@&=+*%()@:![]{}|\^$`
	for _, c := range bannedChars {
		urlPath = strings.ReplaceAll(urlPath, string(c), "")
	}

	return urlPath
}
