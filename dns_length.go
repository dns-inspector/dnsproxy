package dnsproxy

import (
	"encoding/binary"
	"fmt"
	"io"
)

// shared proxy code as DoT and DoQ work the same
func proxyDNSMessageWithLength(proto, remoteAddr string, rw io.ReadWriter) error {
	rawSize := make([]byte, 2)

	if _, err := rw.Read(rawSize); err != nil {
		if serverConfig.Verbosity >= 2 {
			logf(proto, "warn", remoteAddr, "", "error reading message: %s", err.Error())
		}
		return err
	}
	size := binary.BigEndian.Uint16(rawSize)
	if size > 4096 {
		if serverConfig.Verbosity >= 2 {
			logf(proto, "warn", remoteAddr, "", "request too large: %d", size)
		}
		rw.Write([]byte("request too large"))
		return fmt.Errorf("request too large")
	}

	message := make([]byte, size)
	read, err := rw.Read(message)
	if err != nil {
		if serverConfig.Verbosity >= 2 {
			logf(proto, "warn", remoteAddr, "", "error reading message: %s", err.Error())
		}
		return err
	}
	if read != int(size) {
		if serverConfig.Verbosity >= 2 {
			logf(proto, "warn", remoteAddr, "", "invalid message size")
		}
		rw.Write([]byte("invalid message size"))
		return err
	}

	message = append(rawSize, message...)

	reply := processControlQuery(remoteAddr, message)
	if reply == nil {
		var err error
		reply, err = proxyDnsMessage(message)
		if err != nil {
			if serverConfig.Verbosity >= 1 {
				logf(proto, "error", remoteAddr, "", "error proxying message: %s", err.Error())
			}
			return err
		}
	}

	if requestLog != nil {
		requestLog.Record(proto, remoteAddr, message, reply)
	}

	logf(proto, "stats", "", "", "message proxied")
	return nil
}
