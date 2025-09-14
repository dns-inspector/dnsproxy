package dnsproxy

import (
	"fmt"
	"os"
	"time"

	"github.com/ecnepsnai/logtic"
)

func setupLog() {
	if serverConfig.RequestsLogPath != nil {
		if err := requestLog.Open(*serverConfig.RequestsLogPath); err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open requests log file: %s", err.Error())
		}
	}

	logtic.Log.FilePath = serverConfig.LogPath
	switch serverConfig.LogLevel {
	case "debug":
		logtic.Log.Level = logtic.LevelDebug
	case "info":
		logtic.Log.Level = logtic.LevelInfo
	case "warn":
		logtic.Log.Level = logtic.LevelWarn
	case "error":
		logtic.Log.Level = logtic.LevelError
	}
	if err := logtic.Log.Open(); err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open log file: %s", err.Error())
	}
}

func RotateLogs() {
	if requestLog != nil {
		go requestLog.Rotate()
	}

	logtic.Log.RotateDate(time.Now().AddDate(0, 0, -1))
	if serverConfig.CompressRotatedLogs {
		gzipFile(serverConfig.LogPath + "." + time.Now().AddDate(0, 0, -1).Format("2006-01-02"))
	}
}
