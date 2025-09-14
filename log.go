package dnsproxy

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func RotateLog() {
	if requestLog != nil {
		go requestLog.Rotate()
	}

	if logFile == nil {
		return
	}

	rotatedName := fmt.Sprintf("%s.%s", serverConfig.LogPath, time.Now().AddDate(0, 0, -1).Format("2006-01-02"))

	logLock.Lock()
	defer func() {
		logLock.Unlock()
		if serverConfig.CompressRotatedLogs {
			gzipOldLog(rotatedName)
		}
	}()
	logFile.Close()
	logFile = nil

	os.Rename(serverConfig.LogPath, rotatedName)

	if f, err := os.OpenFile(serverConfig.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		logFile = f
	}
}

func gzipOldLog(name string) {
	gzName := name + ".gz"

	in, err := os.Open(name)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.OpenFile(gzName, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return
	}
	defer out.Close()

	w := gzip.NewWriter(out)
	if _, err := io.Copy(w, in); err != nil {
		return
	}

	w.Close()
	os.Remove(name)
}

func logf(proto, level, ip, useragent, format string, args ...any) {
	var message string
	if len(args) > 0 {
		message = fmt.Sprintf(format, args...)
	} else {
		message = format
	}

	values := []string{
		time.Now().UTC().Format("2006-01-02T15:04:05-0700"),
		csvEscape(serverConfig.ServerName),
		level,
		proto,
		ip,
		csvEscape(useragent),
		csvEscape(message),
	}
	line := []byte(strings.Join(values, ",") + "\n")
	os.Stdout.Write(line)
	if logFile != nil {
		logLock.Lock()
		logFile.Write(line)
		logLock.Unlock()
	}
}
