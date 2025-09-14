package dnsproxy

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ecnepsnai/logtic"
)

// shared proxy code as DoT and DoQ work the same
func proxyDNSMessageWithLength(log *logtic.Source, proto, remoteAddr string, rw io.ReadWriter) error {
	rawSize := make([]byte, 2)

	if _, err := rw.Read(rawSize); err != nil {
		log.Debug("Error reading DNS message: %s", err.Error())
		return err
	}
	size := binary.BigEndian.Uint16(rawSize)
	if size > 4096 {
		log.Debug("Error reading DNS message: request too large")
		rw.Write([]byte("request too large"))
		return fmt.Errorf("request too large")
	}

	message := make([]byte, size)
	read, err := rw.Read(message)
	if err != nil {
		log.Debug("Error reading DNS message: %s", err.Error())
		return err
	}
	if read != int(size) {
		log.Debug("Error reading DNS message: invalid message size")
		rw.Write([]byte("invalid message size"))
		return err
	}

	message = append(rawSize, message...)

	reply := processControlQuery(remoteAddr, message)
	if reply == nil {
		var err error
		reply, err = proxyDnsMessage(message)
		if err != nil {
			log.PError("Error proxying DNS message", map[string]any{
				"proto":   proto,
				"from_ip": remoteAddr,
				"error":   err.Error(),
			})
			return err
		}
	}

	if requestLog != nil {
		requestLog.Record(proto, remoteAddr, message, reply)
	}

	log.PDebug("Proxied DNS message", map[string]any{
		"proto":   proto,
		"from_ip": remoteAddr,
	})
	rw.Write(reply)
	return nil
}
