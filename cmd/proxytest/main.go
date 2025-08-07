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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--setup-pki" {
		setupPki()
		return
	}

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
	case "txt":
		messageType = dnsmessage.TypeTXT
	default:
		os.Exit(1)
	}

	buf := make([]byte, 2, 514)
	builder := dnsmessage.NewBuilder(buf, dnsmessage.Header{
		ID:               uint16(mathrand.IntN(65535)),
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

	c, err := tls.Dial("tcp4", server, tlsConfig)
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

func setupPki() {
	pKey, err := ecdsa.GenerateKey(elliptic.P384(), cryptorand.Reader)
	if err != nil {
		panic(err)
	}

	pub := &pKey.PublicKey
	serial := big.NewInt(1)

	privateKeyBytes, err := x509.MarshalECPrivateKey(pKey)
	if err != nil {
		panic(err)
	}

	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		Issuer:                pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().UTC().AddDate(0, 0, -1),
		NotAfter:              time.Now().UTC().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
	}

	certBytes, err := x509.CreateCertificate(cryptorand.Reader, tpl, tpl, pub, pKey)
	if err != nil {
		panic(err)
	}

	os.WriteFile("localhost.crt", pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}), 0644)
	os.WriteFile("localhost.key", pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}), 0644)
}
