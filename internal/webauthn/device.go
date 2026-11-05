package webauthn

import "strings"

// Device is a coarse user-agent classification (LR33b-19) used to decide
// whether a stored platform authenticator belongs to the requesting device.
// OS is one of windows, ios, macos, android or other; Browser one of
// chrome, edge, safari, firefox or other; Class one of phone, tablet or
// desktop. Only Chrome is recognized on Android: another Android browser
// classifies as OS other.
type Device struct {
	OS, Browser, Class string
}

// Key is the recognition key: the OS and the class, plus the browser on
// macOS where platform authenticators are per browser.
func (d Device) Key() string {
	if d.OS == "macos" {
		return d.OS + "/" + d.Browser + "/" + d.Class
	}
	return d.OS + "/" + d.Class
}

// DeviceOf classifies a User-Agent string. Unknown or empty input is
// other/other/desktop.
func DeviceOf(userAgent string) Device {
	ua := strings.ToLower(userAgent)
	d := Device{OS: "other", Browser: "other", Class: "desktop"}
	switch {
	case strings.Contains(ua, "edg/") || strings.Contains(ua, "edga/") || strings.Contains(ua, "edgios/"):
		d.Browser = "edge"
	case strings.Contains(ua, "firefox/") || strings.Contains(ua, "fxios/"):
		d.Browser = "firefox"
	case strings.Contains(ua, "opr/") || strings.Contains(ua, "samsungbrowser/"):
		d.Browser = "other"
	case strings.Contains(ua, "chrome/") || strings.Contains(ua, "crios/"):
		d.Browser = "chrome"
	case strings.Contains(ua, "safari/") && strings.Contains(ua, "applewebkit/"):
		d.Browser = "safari"
	}
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipod"):
		d.OS, d.Class = "ios", "phone"
	case strings.Contains(ua, "ipad"):
		d.OS, d.Class = "ios", "tablet"
	case strings.Contains(ua, "android"):
		d.Class = "tablet"
		if strings.Contains(ua, "mobile") {
			d.Class = "phone"
		}
		if d.Browser == "chrome" {
			d.OS = "android"
		}
	case strings.Contains(ua, "windows nt"):
		d.OS = "windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os x"):
		d.OS = "macos"
	}
	return d
}
