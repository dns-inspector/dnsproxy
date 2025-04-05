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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

func TestParseConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := path.Join(dir, "dnsproxy.conf")

	generateTestCert(path.Join(dir, "localhost.crt"), path.Join(dir, "localhost.key"))

	config := DefaultConfig
	config = strings.ReplaceAll(config, "/etc/dnsproxy/server.crt", path.Join(dir, "localhost.crt"))
	config = strings.ReplaceAll(config, "/etc/dnsproxy/server.key", path.Join(dir, "localhost.key"))

	os.WriteFile(configPath, []byte(config), 0644)

	TestConfig(configPath)
}

func generateTestCert(certPath, keyPath string) {
	pKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

	certBytes, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, pKey)
	if err != nil {
		panic(err)
	}

	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}), 0644)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}), 0644)
}
