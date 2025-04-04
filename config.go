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
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	_ "embed"
)

//go:embed dnsproxy.conf
var DefaultConfig string

type tServerConfig struct {
	CertPath      string
	KeyPath       string
	Verbosity     uint8
	LogPath       string
	DNSServerAddr string
	HTTPSPort     uint16
	TLSPort       uint16
	HTTPRedirect  string
	ServerName    string
	ZabbixHost    *string
}

func (c tServerConfig) Validate() (errors []string) {
	errors = []string{}

	if _, err := os.Stat(c.CertPath); err != nil {
		errors = append(errors, fmt.Sprintf("certificate file does not exist or is unreable: %s", err.Error()))
	}

	if _, err := os.Stat(c.KeyPath); err != nil {
		errors = append(errors, fmt.Sprintf("private key file does not exist or is unreable: %s", err.Error()))
	}

	if c.Verbosity > 3 {
		errors = append(errors, fmt.Sprintf("invalid verbosity level %d, must be one of 0, 1, 2, or 3", c.Verbosity))
	}

	if _, _, err := net.SplitHostPort(c.DNSServerAddr); err != nil {
		errors = append(errors, fmt.Sprintf("invalid dns server address: %s", err.Error()))
	}

	if c.HTTPRedirect != "" {
		u, err := url.Parse(c.HTTPRedirect)
		if err != nil {
			errors = append(errors, fmt.Sprintf("invalid http request: %s", err.Error()))
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			errors = append(errors, fmt.Sprintf("invalid http request: unsupported scheme %s", u.Scheme))
		}
	}

	return errors
}

func TestConfig(configPath string) {
	mustLoadConfig(configPath)
}

func loadConfig(configPath string) (*tServerConfig, []string) {
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil, []string{err.Error()}
	}
	defer configFile.Close()

	config := tServerConfig{}

	errors := []string{}

	scanner := bufio.NewScanner(configFile)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.Trim(parts[0], " ")
		value := strings.Trim(parts[1], " ")

		switch key {
		case "cert_path":
			config.CertPath = value
		case "key_path":
			config.KeyPath = value
		case "verbosity":
			verbosity, err := parseUint8(value)
			if err != nil {
				errors = append(errors, fmt.Sprintf("invalid verbosity value: %s", value))
			}
			config.Verbosity = verbosity
		case "log_path":
			config.LogPath = value
		case "dns_server_addr":
			config.DNSServerAddr = value
		case "https_port":
			httpsport, err := parseUint16(value)
			if err != nil {
				errors = append(errors, fmt.Sprintf("invalid https_port value: %s", value))
			}
			config.HTTPSPort = httpsport
		case "tls_port":
			tlsport, err := parseUint16(value)
			if err != nil {
				errors = append(errors, fmt.Sprintf("invalid tls_port value: %s", value))
			}
			config.TLSPort = tlsport
		case "http_redirect":
			config.HTTPRedirect = value
		case "server_name":
			config.ServerName = value
		case "zabbix_server":
			config.ZabbixHost = &value
		default:
			continue
		}
	}

	errors = append(errors, config.Validate()...)

	if len(errors) > 0 {
		return nil, errors
	}

	return &config, nil
}

func mustLoadConfig(configPath string) *tServerConfig {
	config, configErrors := loadConfig(configPath)
	if len(configErrors) > 0 {
		fmt.Fprintf(os.Stderr, "Configuration errors found:\n")
		for _, err := range configErrors {
			fmt.Fprintf(os.Stderr, "- %s\n", err)
		}
		os.Exit(1)
	}
	return config
}

func parseUint8(str string) (uint8, error) {
	v, err := strconv.ParseUint(str, 10, 8)
	return uint8(v), err
}

func parseUint16(str string) (uint16, error) {
	v, err := strconv.ParseUint(str, 10, 16)
	return uint16(v), err
}
