//go:build android
// +build android

package libtailscale

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/netns"
)

func setProtectFunc(f func(fd int) error) {
	netns.SetAndroidProtectFunc(f)
}

func createTUNFromFD(fd int) (tun.Device, string, error) {
	return tun.CreateUnmonitoredTUNFromFD(fd)
}