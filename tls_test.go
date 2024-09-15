package dnsproxy

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"testing"
)

func TestTLS(t *testing.T) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "127.0.0.1:8853", tlsConfig)
	if err != nil {
		t.Errorf("Error connecting to DOT: %s", err.Error())
		return
	}

	var outLength = make([]byte, 2)
	binary.BigEndian.PutUint16(outLength, uint16(len(dnsMessage)))
	conn.Write(outLength)
	conn.Write(dnsMessage)

	inLength := make([]byte, 2)
	if _, err := conn.Read(inLength); err != nil {
		t.Errorf("Error connecting to DOT: %s", err.Error())
		return
	}
	reply := make([]byte, int(binary.BigEndian.Uint16(inLength)))
	if _, err := conn.Read(reply); err != nil {
		t.Errorf("Error connecting to DOT: %s", err.Error())
		return
	}

	assertExpectedReply(reply, t)
}

func TestTLSExcessiveBody(t *testing.T) {
	var body = make([]byte, 4097)
	if _, err := rand.Read(body); err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "127.0.0.1:8853", tlsConfig)
	if err != nil {
		t.Errorf("Error connecting to DOT: %s", err.Error())
		return
	}

	var outLength = make([]byte, 2)
	binary.BigEndian.PutUint16(outLength, uint16(len(body)))
	conn.Write(outLength)
	conn.Write(body)
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Errorf("Error connecting to DOT: %s", err.Error())
		return
	}

	if string(reply) != "request too large" {
		t.Errorf("Unexpected reply")
		return
	}
}

func TestTLSWrongBody(t *testing.T) {
	var body = make([]byte, 16)
	if _, err := rand.Read(body); err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "127.0.0.1:8853", tlsConfig)
	if err != nil {
		t.Errorf("Error connecting to DOT: %s", err.Error())
		return
	}

	var outLength = make([]byte, 2)
	binary.BigEndian.PutUint16(outLength, uint16(128))
	conn.Write(outLength)
	conn.Write(body)
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Errorf("Error connecting to DOT: %s", err.Error())
		return
	}

	if string(reply) != "invalid message size" {
		t.Errorf("Unexpected reply")
		return
	}
}
