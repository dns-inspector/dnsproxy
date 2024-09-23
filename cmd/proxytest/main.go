package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	if len(os.Args) != 4 {
		os.Exit(1)
	}

	server := os.Args[1]
	recordType := os.Args[2]
	name := os.Args[3]

	var messageType dnsmessage.Type
	switch strings.ToLower(recordType) {
	case "a":
		messageType = dnsmessage.TypeA
	case "aaaa":
		messageType = dnsmessage.TypeAAAA
	case "mx":
		messageType = dnsmessage.TypeMX
	default:
		os.Exit(1)
	}

	buf := make([]byte, 2, 514)
	builder := dnsmessage.NewBuilder(buf, dnsmessage.Header{
		ID:               uint16(rand.IntN(65535)),
		OpCode:           0,
		RecursionDesired: true,
	})
	builder.EnableCompression()
	builder.StartQuestions()
	builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  messageType,
		Class: dnsmessage.ClassINET,
	})
	builder.StartAnswers()
	builder.StartAdditionals()
	buf, err := builder.Finish()
	if err != nil {
		panic(err)
	}

	message := buf[2:]

	if strings.HasPrefix(server, "https://") {
		doh(server, message)
		return
	}

	dot(server, message)
}

func dot(server string, message []byte) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	c, err := tls.Dial("tcp", server, tlsConfig)
	if err != nil {
		panic(err)
	}

	var outLengthRaw = make([]byte, 2)
	binary.BigEndian.PutUint16(outLengthRaw, uint16(len(message)))

	c.Write(outLengthRaw)
	c.Write(message)

	var inLengthRaw = make([]byte, 2)
	if _, err := c.Read(inLengthRaw); err != nil {
		panic(err)
	}
	inLength := binary.BigEndian.Uint16(inLengthRaw)

	var reply = make([]byte, inLength)
	if _, err := c.Read(reply); err != nil {
		panic(err)
	}

	printReply(reply)
}

func doh(server string, message []byte) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	encodedMessage := base64.RawURLEncoding.EncodeToString(message)
	url := server + "?dns=" + encodedMessage
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode != 200 {
		panic("http error: " + resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	printReply(body)
}

func printReply(reply []byte) {
	p := &dnsmessage.Parser{}
	header, err := p.Start(reply)
	if err != nil {
		panic(err)
	}
	fmt.Println("Header:")
	fmt.Println(header.GoString())
	fmt.Println("")

	fmt.Println("Questions:")
	for {
		q, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			panic(err)
		}

		fmt.Println(q.GoString())
	}
	fmt.Println("")

	fmt.Println("Answers:")
	for {
		a, err := p.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			panic(err)
		}

		fmt.Println(a.GoString())
	}
	fmt.Println("")
}