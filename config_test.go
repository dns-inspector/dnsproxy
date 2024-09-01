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

	os.WriteFile(path.Join(dir, "server.crt"), []byte("1"), 0644)
	os.WriteFile(path.Join(dir, "server.key"), []byte("1"), 0644)

	config := DefaultConfig
	config = strings.ReplaceAll(config, "/etc/dnsproxy/server.crt", path.Join(dir, "server.crt"))
	config = strings.ReplaceAll(config, "/etc/dnsproxy/server.key", path.Join(dir, "server.key"))

	os.WriteFile(configPath, []byte(config), 0644)

	TestConfig(configPath)
}
