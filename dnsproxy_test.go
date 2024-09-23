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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if _, err := os.Stat("localhost.crt"); err != nil {
		setupPki()
	}

	go Start("dnsproxy_test.conf")
	time.Sleep(10 * time.Millisecond)
	result := m.Run()
	Stop(false)
	os.Exit(result)
}

func setupPki() {
	pKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}

	pub := &pKey.PublicKey
	serial := big.NewInt(1)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	h := sha1.Sum(publicKeyBytes)

	privateKeyBytes, err := x509.MarshalECPrivateKey(pKey)
	if err != nil {
		panic(err)
	}

	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Now().UTC().AddDate(100, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
		SubjectKeyId:          h[:],
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, pKey)
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

var dnsMessage = []byte{0xd6, 0xdf, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00}
var expectedDnsReply = [39]byte{0x00, 0xa3, 0xd6, 0xdf, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00}

func assertExpectedReply(reply []byte, t *testing.T) {
	if len(reply) < 39 {
		t.Errorf("Unexpectedly short reply")
		return
	}

	if bytes.Equal(reply[:39], expectedDnsReply[:]) {
		t.Errorf("Unexpected reply")
		t.Logf("Expected: % 02x", expectedDnsReply)
		t.Logf("Got: % 02x", reply[:39])
		return
	}
}
