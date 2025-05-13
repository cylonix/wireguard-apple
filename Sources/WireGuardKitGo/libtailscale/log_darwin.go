//go:build darwin
// +build darwin

package libtailscale

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

const logLineLimit = 1024

var ID = filepath.Base(os.Args[0])

// Temp file for stderr
var stderrFile *os.File
var replaceStderrWithFilch = false

func initLogging(appCtx AppContext, logDir string) {
	tag := ID + ":" + "initLogging"
	defer func() {
		if r := recover(); r != nil {
			stack := string(debug.Stack())
			appCtx.Log(tag, fmt.Sprintf("PANIC in initLogging: %v\n%s", r, stack))
		}
	}()

	appCtx.Log(tag, "initLogging started")

	// Set up temp file with synchronous writes
	stderrPath := filepath.Join(logDir, "stderr.log")

	// Log any previous stderr content from a prior crash
	appCtx.Log(tag, "Checking for previous stderr output at: "+stderrPath)
	if data, err := os.ReadFile(stderrPath); err == nil && len(data) > 0 {
		appCtx.Log(tag, "Found previous stderr output from crash:")
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if line != "" {
				appCtx.Log(tag+": RECOVERED:", line)
			}
		}
		// Optionally truncate after logging; comment out if you want to append
		os.Truncate(stderrPath, 0)
	}

	var err error
	// Open with O_SYNC to ensure writes are flushed to disk immediately
	stderrFile, err = os.OpenFile(stderrPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_SYNC, 0644)
	if err != nil {
		appCtx.Log(tag, fmt.Sprintf("Failed to create stderr temp file: %v", err))
		return
	}

	// Redirect os.Stderr to the temp file
	if err := syscall.Dup2(int(stderrFile.Fd()), syscall.Stderr); err != nil {
		appCtx.Log(tag, fmt.Sprintf("Failed to redirect stderr to temp file: %v", err))
		return
	}
	os.Stderr = stderrFile

	// Start tailing the stderr file
	go tailStderrFile(appCtx, stderrPath)

	logWriter := &logWriter{appCtx: appCtx}
	_, err = logWriter.Write([]byte("Test log write"))
	if err != nil {
		appCtx.Log(tag, fmt.Sprintf("Log writer test failed: %v", err))
		return
	}

	log.SetFlags(log.Flags() &^ log.LstdFlags)
	log.SetOutput(logWriter)

	appCtx.Log(tag, "Log output redirected")

	if err := redirectStdoutStderr(appCtx); err != nil {
		appCtx.Log(tag, fmt.Sprintf("Failed to redirect stdout/stderr: %v", err))
	}

	appCtx.Log(tag, "initLogging completed")

	// Test panic in a random goroutine
	go func() {
		time.Sleep(2 * time.Second)
		appCtx.Log(tag, "Test stderr redirection")
		fmt.Fprintf(os.Stderr, "Test message written to stderr\n")
	}()

	// Handle signals for graceful exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGABRT)
	go func() {
		<-sigs
		stderrFile.Write([]byte("Received exit signal! Closing stderr file."))
		stderrFile.Close()
		os.Exit(1)
	}()
}

func redirectStdoutStderr(appCtx AppContext) error {
	if err := logFd(os.Stdout.Fd(), appCtx, "STDOUT"); err != nil {
		return fmt.Errorf("stdout redirect failed: %w", err)
	}
	// Stderr is already redirected to the temp file
	return nil
}

func logFd(fd uintptr, appCtx AppContext, fdName string) error {
	tag := ID + ":" + fdName
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe creation failed: %w", err)
	}

	ready := make(chan struct{})
	done := make(chan error, 1)

	go func() {
		defer func() {
			appCtx.Log(tag, "Exiting redirect go routine")
			r.Close()
			close(done)
		}()

		appCtx.Log(tag, "Reader started")
		close(ready)

		buf := make([]byte, 65536)
		for {
			n, err := r.Read(buf)
			if err != nil {
				appCtx.Log(tag, fmt.Sprintf("Read error: %v", err))
				return
			}
			if n > 0 {
				lines := strings.Split(string(buf[:n]), "\n")
				for _, line := range lines {
					if line != "" {
						appCtx.Log(tag, line)
					}
				}
			}
		}
	}()

	<-ready
	appCtx.Log(tag, "Reader confirmed ready")

	oldFd, err := syscall.Dup(int(fd))
	if err != nil {
		w.Close()
		return fmt.Errorf("failed to dup old fd: %w", err)
	}

	if err := syscall.Dup2(int(w.Fd()), int(fd)); err != nil {
		syscall.Close(oldFd)
		w.Close()
		return fmt.Errorf("dup2 failed: %w", err)
	}

	runtime.SetFinalizer(w, func(w *os.File) {
		appCtx.Log(tag, "closing redirect writer")
		w.Close()
	})

	return nil
}

func tailStderrFile(appCtx AppContext, stderrPath string) {
	tag := ID + ":STDERR"
	buf := make([]byte, 65536)
	var offset int64

	// Open a separate handle for reading
	tailFile, err := os.OpenFile(stderrPath, os.O_RDONLY|os.O_SYNC, 0)
	if err != nil {
		appCtx.Log(tag, fmt.Sprintf("Failed to open stderr file for tailing: %v", err))
		return
	}
	appCtx.Log(tag, "Opened stderr file for tailing:"+stderrPath)
	defer tailFile.Close()

	for {
		_, err := tailFile.Seek(offset, 0)
		if err != nil {
			appCtx.Log(tag, fmt.Sprintf("Seek error: %v", err))
			return
		}

		n, err := tailFile.Read(buf)
		if err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, io.EOF) {
			appCtx.Log(tag, fmt.Sprintf("Read error: %v", err))
			return
		}
		if n > 0 {
			appCtx.Log(tag, fmt.Sprintf("READ %v bytes", n))
			lines := strings.Split(string(buf[:n]), "\n")
			for _, line := range lines {
				if line != "" {
					appCtx.Log(tag, line)
				}
			}
			offset += int64(n)
		}

		time.Sleep(1 * time.Second)
	}
}

type logWriter struct {
	appCtx AppContext
}

func (w *logWriter) Write(data []byte) (int, error) {
	n := 0
	tag := ID
	for len(data) > 0 {
		msg := data
		if len(msg) > logLineLimit {
			msg = msg[:logLineLimit]
		}
		w.appCtx.Log(tag, string(msg))
		n += len(msg)
		data = data[len(msg):]
	}
	return n, nil
}
