package dnsproxy

import "testing"

func TestSanitizePath(t *testing.T) {
	check := func(in, expect string) {
		actual := sanitizePath(in)
		if expect != actual {
			t.Errorf("Unexpected result from sanitizePath. Expected '%s' got '%s'", expect, actual)
		}
	}

	check("/../../../../etc/shadow", "/etc/shadow")
	check("/.../.../.../.../.../.../.../.../.../windows/win.ini", "/.........windows/win.ini")
	check(`\\localhost\c$\windows\win.ini`, "localhostcwindowswin.ini")
}
