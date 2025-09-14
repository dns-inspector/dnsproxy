package dnsproxy

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type requestLogWriter struct {
	f        *os.File
	filePath string
	lock     *sync.Mutex
}

var requestLog *requestLogWriter

func (w *requestLogWriter) Open(filePath string) error {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	w.filePath = filePath
	w.f = f
	w.lock = &sync.Mutex{}
	return nil
}

func (w *requestLogWriter) Rotate() {
	rotatedName := fmt.Sprintf("%s.%s", w.filePath, time.Now().AddDate(0, 0, -1).Format("2006-01-02"))

	w.lock.Lock()
	defer func() {
		w.lock.Unlock()
		if serverConfig.CompressRotatedLogs {
			gzipFile(rotatedName)
		}
	}()
	w.f.Sync()
	w.f.Close()
	w.f = nil

	os.Rename(w.filePath, rotatedName)

	if f, err := os.OpenFile(w.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		w.f = f
	}
}

func (w *requestLogWriter) Record(proto, ip string, query, reply []byte) {
	values := []string{
		time.Now().UTC().Format("2006-01-02T15:04:05-0700"),
		csvEscape(serverConfig.ServerName),
		proto,
		csvEscape(ip),
		fmt.Sprintf("%x", query),
		fmt.Sprintf("%x", reply),
	}

	line := []byte(strings.Join(values, ",") + "\n")
	os.Stdout.Write(line)
	w.lock.Lock()
	w.f.Write(line)
	w.lock.Unlock()
}

func csvEscape(in string) string {
	if in != "" && strings.ContainsAny(in, ",\"\n") {
		in = strings.ReplaceAll(in, ",", "__COMMA__")
		in = strings.ReplaceAll(in, "\"", "__QUOTE__")
		in = strings.ReplaceAll(in, "\n", "__NEWLINE__")
	}

	return in
}

func gzipFile(name string) error {
	gzName := name + ".gz"

	in, err := os.Open(name)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(gzName, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	w := gzip.NewWriter(out)
	if _, err := io.Copy(w, in); err != nil {
		return err
	}

	w.Close()
	os.Remove(name)
	return nil
}
