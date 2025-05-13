//go:build !android && !darwin
// +build !android,!darwin

package libtailscale

import (
	"errors"

	"github.com/tailscale/wireguard-go/tun"
)

func setProtectFunc(func(fd int) error) {
}

func createTUNFromFD(fd int) (tun.Device, string, error) {
	return nil, "", errors.New("not implemented")
}