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
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"testing"
)

func TestHTTPSGet(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://127.0.0.1:8443/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(dnsMessage))
	if err != nil {
		t.Errorf("Error connecting to DOH: %s", err.Error())
		return
	}

	if resp.StatusCode != 200 {
		t.Errorf("Unexpected HTTP response code %d", resp.StatusCode)
		return
	}

	if contentType := resp.Header.Get("Content-Type"); contentType != "application/dns-message" {
		t.Errorf("Unexpected HTTP response content type %s", contentType)
		return
	}

	reply, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("Error reading response body: %s", err.Error())
		return
	}

	assertExpectedReply(reply, t)
}

func TestHTTPSPost(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Post("https://127.0.0.1:8443/dns-query", "application/dns-message", bytes.NewBuffer(dnsMessage))
	if err != nil {
		t.Errorf("Error connecting to DOH: %s", err.Error())
		return
	}

	if resp.StatusCode != 200 {
		t.Errorf("Unexpected HTTP response code %d", resp.StatusCode)
		return
	}

	if contentType := resp.Header.Get("Content-Type"); contentType != "application/dns-message" {
		t.Errorf("Unexpected HTTP response content type %s", contentType)
		return
	}

	reply, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("Error reading response body: %s", err.Error())
		return
	}

	assertExpectedReply(reply, t)
}

func TestHTTPSRedirect(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("https://127.0.0.1:8443/")
	if err != nil {
		t.Errorf("Error connecting to DOH: %s", err.Error())
		return
	}

	if resp.StatusCode != 302 {
		t.Errorf("Unexpected HTTP response code %d", resp.StatusCode)
		return
	}

	if location := resp.Header.Get("Location"); location != "https://example.com" {
		t.Errorf("Unexpected HTTP redirect: %s", location)
		return
	}
}

func TestHTTPSGetMissingQuery(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://127.0.0.1:8443/dns-query?foo=bar")
	if err != nil {
		t.Errorf("Error connecting to DOH: %s", err.Error())
		return
	}

	if resp.StatusCode != 400 {
		t.Errorf("Unexpected HTTP response code %d", resp.StatusCode)
		return
	}
}

func TestHTTPSGetInvalidQuery(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://127.0.0.1:8443/dns-query?dns=^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
	if err != nil {
		t.Errorf("Error connecting to DOH: %s", err.Error())
		return
	}

	if resp.StatusCode != 400 {
		t.Errorf("Unexpected HTTP response code %d", resp.StatusCode)
		return
	}
}

func TestHTTPSGetShortQuery(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://127.0.0.1:8443/dns-query?dns=baz")
	if err != nil {
		t.Errorf("Error connecting to DOH: %s", err.Error())
		return
	}

	if resp.StatusCode != 400 {
		t.Errorf("Unexpected HTTP response code %d", resp.StatusCode)
		return
	}
}

func TestHTTPSPostExcessiveBody(t *testing.T) {
	var body = make([]byte, 4097)
	if _, err := rand.Read(body); err != nil {
		panic(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Post("https://127.0.0.1:8443/dns-query", "application/dns-message", bytes.NewBuffer(body))
	if err != nil {
		t.Errorf("Error connecting to DOH: %s", err.Error())
		return
	}

	if resp.StatusCode != 400 {
		t.Errorf("Unexpected HTTP response code %d", resp.StatusCode)
		return
	}
}
