package dnsproxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/dns/dnsmessage"
)

var (
	controlZoneIp      = ""
	controlZoneTime    = ""
	controlZoneUuid    = ""
	controlZoneVersion = ""
)

func processControlQuery(remoteAddr string, message []byte) []byte {
	if serverConfig.ControlZone == nil {
		return nil
	}

	m := &dnsmessage.Message{}
	if err := m.Unpack(message[2:]); err != nil {
		return nil
	}
	if len(m.Questions) != 1 {
		return nil
	}
	q := m.Questions[0]
	if q.Type != dnsmessage.TypeTXT || q.Class != dnsmessage.ClassINET {
		return nil
	}

	replyData := ""

	switch q.Name.String() {
	case controlZoneIp:
		h, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			replyData = remoteAddr
		} else {
			replyData = h
		}
	case controlZoneUuid:
		replyData = uuid.NewString()
	case controlZoneTime:
		replyData = time.Now().UTC().Format(time.RFC3339)
	case controlZoneVersion:
		replyData = fmt.Sprintf("%s (Variant: %s-%s, Built on: %s, Revision: %s)", Version, runtime.GOOS, runtime.GOARCH, BuiltOn, Revision)
	default:
		return nil
	}

	header := m.Header
	header.Response = true
	builder := dnsmessage.NewBuilder(nil, header)
	builder.EnableCompression()
	builder.StartQuestions()
	builder.Question(m.Questions[0])
	builder.StartAnswers()
	builder.TXTResource(dnsmessage.ResourceHeader{
		Name:  dnsmessage.MustNewName(q.Name.String()),
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
		TTL:   0,
	}, dnsmessage.TXTResource{
		TXT: []string{replyData},
	})
	builder.StartAdditionals()
	reply, err := builder.Finish()
	if err != nil {
		return nil
	}

	rawSize := make([]byte, 2)
	binary.BigEndian.PutUint16(rawSize, uint16(len(reply)))

	return append(rawSize, reply...)
}
