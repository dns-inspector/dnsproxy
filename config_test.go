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
	"os"
	"path"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := path.Join(dir, "dnsproxy.conf")

	config := DefaultConfig
	config = strings.ReplaceAll(config, "/etc/dnsproxy/server.crt", path.Join(dir, "localhost.crt"))
	config = strings.ReplaceAll(config, "/etc/dnsproxy/server.key", path.Join(dir, "localhost.key"))

	os.WriteFile(configPath, []byte(config), 0644)

	TestConfig(configPath)
}
