//go:build darwin
// +build darwin

package libtailscale

import (
	"fmt"
	"os"

	"github.com/tailscale/wireguard-go/tun"
)

func setProtectFunc(func(fd int) error) {}
func createTUNFromFD(fd int) (tun.Device, string, error) {
    // Validate fd before creating TUN device
    if fd < 0 {
        return nil, "", fmt.Errorf("invalid file descriptor: %d", fd)
    }

    // Create new file from fd with proper cleanup
    tunFile := os.NewFile(uintptr(fd), "/dev/tun")
    if tunFile == nil {
        return nil, "", fmt.Errorf("failed to create file from fd: %d", fd)
    }

    // Ensure file is closed if device creation fails
    var device tun.Device
    var err error
    defer func() {
        if err != nil && tunFile != nil {
            tunFile.Close()
        }
    }()

    // Create TUN device
    device, err = tun.CreateTUNFromFile(tunFile, 0)
    if err != nil {
        return nil, "", fmt.Errorf("create TUN from file failed: %w", err)
    }

    return device, "", nil
}
