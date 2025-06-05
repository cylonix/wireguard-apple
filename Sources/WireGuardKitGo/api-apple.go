/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
// static void callAdapter(void *func, void *ctx, const char *method, const char *args, char *resp_buf, int resp_buf_len) {
//	((void(*)(void *, const char *, const char *, char *, int))func)(ctx, method, args, resp_buf, resp_buf_len);
// }
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
	"unsafe"

	"net/http"
	_ "net/http/pprof"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

var (
	loggerFunc  unsafe.Pointer
	loggerCtx   unsafe.Pointer
	adapterFunc unsafe.Pointer
	adapterCtx  unsafe.Pointer
)

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func cstringFromBytes(b []byte) *C.char {
	return (*C.char)(unsafe.Pointer(&b[0]))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

type tunnelHandle struct {
	*device.Device
	*device.Logger
}

var tunnelHandles = make(map[int32]tunnelHandle)

func init() {
	log.Printf("=========== Network extension coming to life ===========")
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

// wgLogWriter implements the io.Writer interface to redirect golang logging
// output to system passed in log handler
type wgLogWriter struct{}

func (w *wgLogWriter) Write(p []byte) (n int, err error) {
	if uintptr(loggerFunc) == 0 {
		// silently drop the message
		return 0, nil
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(0), cstring(string(p)))
	return len(p), nil
}

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
	log.Printf("Set logger func %v", loggerFunc)
	if uintptr(loggerFunc) == 0 {
		// TODO filch may have cached us. Need to look into that
		if _, ok := log.Writer().(*wgLogWriter); ok {
			log.SetOutput(os.Stderr)
		}
	} else {
		log.SetOutput(&wgLogWriter{})
	}
	debug.SetGCPercent(10)
}

var (
	useCylonixBackend = true
	turnOnProfiling   = false
	groupFolder       string
	systemInfo        SystemInfo
	errorLogf         = CLogger(1).Printf
)

type SystemInfo struct {
	SharedFolderURL string `json:"shared_folder_url"`
	OSVersion       string `json:"os_version"`
	DeviceModel     string `json:"device_model"`
}

//export wgSetAdapter
func wgSetAdapter(sysInfo *C.char, context, adapterFn uintptr) {
	adapterCtx = unsafe.Pointer(context)
	adapterFunc = unsafe.Pointer(adapterFn)

	// Decode system info JSON
	sysInfoStr := C.GoString(sysInfo)
	if err := json.Unmarshal([]byte(sysInfoStr), &systemInfo); err != nil {
		log.Printf("Error decoding system info: %v", err)
	} else {
		log.Printf("System info received: %+v", systemInfo)
	}

	// Set group folder from shared folder URL
	groupFolder = systemInfo.SharedFolderURL
	log.Printf("Set up adapter callback groupFolder=%v adapterFn=%v", groupFolder, adapterFn)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	log.Printf("in wgTurnOn....... fd=%v savedFd=%v", tunFd, savedTunFd)

	if useCylonixBackend {
		return initCylonixBackend(tunFd)
	}

	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)

	err = dev.IpcSet(C.GoString(settings))
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	dev.Up()
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		unix.Close(dupTunFd)
		return -1
	}
	tunnelHandles[i] = tunnelHandle{dev, logger}
	return i
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	if useCylonixBackend {
		log.Printf("Turn off called")
		turnOffVPN()
		return
	}
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)
	dev.Close()
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	if useCylonixBackend {
		log.Printf("Set config called. Ignored")
		return 0
	}

	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return 0
	}
	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	device, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	if useCylonixBackend {
		log.Printf("Bump socket called. Ignored")
		return
	}
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.BindUpdate()
			if err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				clogf("bump socket: success!")
				return
			}
			dev.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	if useCylonixBackend {
		log.Printf("Disable roaming called. Ignored")
		return
	}

	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
}

//export wgVersion
func wgVersion() *C.char {
	if useCylonixBackend {
		return C.CString(cylonixVersion())
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

//export wgSendCommand
func wgSendCommand(cmd *C.char, args *C.char) *C.char {
	// Create a channel for the result
	resultCh := make(chan string, 1)
	goCmd := C.GoString(cmd)

	// TODO: let the caller specify the timeout
	// For now, set the timeout to 24 hours for send file command.
	timeout := getCmdTimeout(goCmd)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Run handleCommand in a goroutine
	go func() {
		result := handleCommand(goCmd, C.GoString(args))
		select {
		case resultCh <- result:
		case <-ctx.Done():
			// Context cancelled, don't send result
		}
	}()

	// Wait for either result or timeout
	select {
	case result := <-resultCh:
		if !shouldSkipSendCommandLog(goCmd) {
			s := result
			if len(result) > 256 {
				s = result[:256]
			}
			log.Printf("send command '%v' result: %v", goCmd, s)
		}
		return C.CString(result)
	case <-ctx.Done():
		log.Printf("[ERROR] send command '%v' timed out after 5 seconds", goCmd)
		return C.CString(`{"error": "command timed out"}`)
	}
}

func shouldSkipSendCommandLog(cmd string) bool {
	switch cmd {
	case "log":
		return true
	default:
		return false
	}
}

func callWgAdapter(method, args string) ([]byte, error) {
	if adapterFunc == nil || adapterCtx == nil {
		return nil, errors.New("adapter function not set")
	}

	cMethod := cstring(method)
	cArgs := cstring(args)
	cRespBuf := cstringFromBytes(make([]byte, 4096))
	C.callAdapter(adapterFunc, adapterCtx, cMethod, cArgs, cRespBuf, 4096)
	resp := C.GoString(cRespBuf)
	if strings.HasPrefix(resp, "ERROR: ") {
		s := args
		if len(args) > 64 {
			s = args[:64] + "..."
		}
		log.Printf("Call adapter for %v(%v) failed: %v", method, s, resp)
		errMsg := strings.TrimPrefix(resp, "ERROR: ")
		return nil, errors.New(errMsg)
	}
	resp = strings.TrimPrefix(resp, "SUCCESS: ")
	return []byte(resp), nil
}

func main() {
	log.Printf("starting the network extension go routine")
	// We aren't very performance sensitive, and the parts that are
	// performance sensitive (wireguard) try hard not to do any memory
	// allocations. So let's be aggressive about garbage collection,
	// unless the user specifically overrides it in the usual way.
	if _, ok := os.LookupEnv("GOGC"); !ok {
		debug.SetGCPercent(10)
	}

	// Refer to https://tailscale.com/blog/go-linker/
	// Although we are getting 50MB in ios 15.1, it is worth to make versions
	// older that has 15MB network extension memory limit works too.
	// Set max proc to 1.
	//runtime.GOMAXPROCS(1)
	if turnOnProfiling {
		go func() {
			log.Println("Starting pprof service")
			log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
		}()
	}
}
