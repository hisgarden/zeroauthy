package webauthn_test

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/webauthn"
)

const (
	uaWindowsChrome  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	uaWindowsEdge    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.2849.56"
	uaWindowsFirefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0"
	uaMacSafari      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
	uaMacChrome      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	uaMacEdge        = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.2849.56"
	uaMacFirefox     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:130.0) Gecko/20100101 Firefox/130.0"
	uaIPhone         = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
	uaIPhoneChrome   = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.6723.37 Mobile/15E148 Safari/604.1"
	uaIPad           = "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
	uaAndroidChrome  = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
	uaAndroidTablet  = "Mozilla/5.0 (Linux; Android 14; SM-X910) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	uaAndroidFirefox = "Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0"
	uaAndroidSamsung = "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36"
	uaLinuxFirefox   = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"
	uaChromeOS       = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

func TestDeviceOf(t *testing.T) {
	for _, tc := range []struct {
		name, ua, os, browser, class, key string
	}{
		{"windows chrome", uaWindowsChrome, "windows", "chrome", "desktop", "windows/desktop"},
		{"windows edge", uaWindowsEdge, "windows", "edge", "desktop", "windows/desktop"},
		{"windows firefox", uaWindowsFirefox, "windows", "firefox", "desktop", "windows/desktop"},
		{"macos safari", uaMacSafari, "macos", "safari", "desktop", "macos/safari/desktop"},
		{"macos chrome", uaMacChrome, "macos", "chrome", "desktop", "macos/chrome/desktop"},
		{"macos edge", uaMacEdge, "macos", "edge", "desktop", "macos/edge/desktop"},
		{"macos firefox", uaMacFirefox, "macos", "firefox", "desktop", "macos/firefox/desktop"},
		{"iphone", uaIPhone, "ios", "safari", "phone", "ios/phone"},
		{"iphone chrome", uaIPhoneChrome, "ios", "chrome", "phone", "ios/phone"},
		{"ipad", uaIPad, "ios", "safari", "tablet", "ios/tablet"},
		{"android chrome", uaAndroidChrome, "android", "chrome", "phone", "android/phone"},
		{"android tablet chrome", uaAndroidTablet, "android", "chrome", "tablet", "android/tablet"},
		{"android firefox", uaAndroidFirefox, "other", "firefox", "phone", "other/phone"},
		{"android samsung", uaAndroidSamsung, "other", "other", "phone", "other/phone"},
		{"linux firefox", uaLinuxFirefox, "other", "firefox", "desktop", "other/desktop"},
		{"chrome os", uaChromeOS, "other", "chrome", "desktop", "other/desktop"},
		{"empty", "", "other", "other", "desktop", "other/desktop"},
		{"garbage", "curl/8.0", "other", "other", "desktop", "other/desktop"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := webauthn.DeviceOf(tc.ua)
			if d.OS != tc.os || d.Browser != tc.browser || d.Class != tc.class {
				t.Fatalf("got %+v want {%s %s %s}", d, tc.os, tc.browser, tc.class)
			}
			if d.Key() != tc.key {
				t.Fatalf("key %q want %q", d.Key(), tc.key)
			}
		})
	}
	if webauthn.DeviceOf(uaWindowsChrome).Key() != webauthn.DeviceOf(uaWindowsEdge).Key() {
		t.Fatal("windows chrome and edge must share a key")
	}
	if webauthn.DeviceOf(uaMacSafari).Key() == webauthn.DeviceOf(uaMacChrome).Key() {
		t.Fatal("macos safari and chrome must differ")
	}
	if webauthn.DeviceOf(uaIPhone).Key() == webauthn.DeviceOf(uaIPad).Key() {
		t.Fatal("iphone and ipad must differ")
	}
}
