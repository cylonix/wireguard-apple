// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailchat

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/net/netns"
)

const (
	ackInterval    = time.Millisecond * 500
	fileBufferSize = 1024 * 64
)

var (
	bufferMutex     = &sync.Mutex{}
	wantRunning     = false
	isRunning       = false
	logger          = log.New(os.Stdout, "tailchat: ", log.LstdFlags)
	stopChannel     = make(chan struct{})
	subscribers     = make(map[net.Conn](chan struct{}))
	connections	    = make(map[net.Conn]struct{})
	connectionMutex = &sync.RWMutex{}
	subscriberMutex = &sync.RWMutex{}
	cacheDir        string
	bufferFilePath  string
	tunnelIndex	    = -1
	startArgs       StartArgs

	// notifyTailchatAppFunc is a function to notify the Tailchat app
	notifyTailchatAppFunc = func(string){}
)

// Message passed among functions are without the trailing '\n'
type StartArgs struct {
	Port           int
	SubscriberPort int
	CacheDir       string
}

func IsRunning() bool {
	return isRunning
}

func TunnelUpdated(index int) {
	logger.Println("Tunnel index updated to", index)
	tunnelIndex = index
	if isRunning {
		logger.Println("Tunnel index updated. Restarting the service")
		Stop()
		time.Sleep(1 * time.Second) // Give some time to stop
		Start(startArgs)
	} else if wantRunning {
		logger.Println("Tunnel index updated. Starting the service")
		Start(startArgs)
	} else {
		logger.Println("Tunnel index updated. Service is not set to run. Nothing to do")
	}
}

func ClearTunnelIndex() {
	logger.Println("Clearing tunnel index")
	tunnelIndex = -1
}

func Start(args StartArgs) error {
	logger.Println("Starting the service")

	if isRunning {
		if startArgs.Port == args.Port && startArgs.SubscriberPort == args.SubscriberPort && startArgs.CacheDir == args.CacheDir {
			logger.Println("Service is already started with the same arguments. Nothing to do")
			return nil
		}
		logger.Println("Service is already started with different arguments. Stopping it first")
		Stop()
		time.Sleep(1 * time.Second) // Give some time to stop
		logger.Println("Service stopped. Now starting it again")
	}
	wantRunning = true
	startArgs = args
	port := 50311
	subscriberPort := 50312
	if args.Port > 0 {
		port = args.Port
	}
	if args.SubscriberPort > 0 {
		subscriberPort = args.SubscriberPort
	}
	cacheDir = args.CacheDir
	if cacheDir == "" {
		logger.Println("Cache dir is not set. Cannot start the service")
		return fmt.Errorf("cache dir is not set")
	}
	logger.Println("Cache dir is", cacheDir)
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			logger.Println("Error creating cache directory: ", err)
			return err
		}
	}
	bufferFilePath = filepath.Join(cacheDir, ".tailchat_buffer.json")
	if tunnelIndex < 0 {
		logger.Println("Tunnel index is not set. Will wait for it to be set")
		return nil
	}
	var lc net.ListenConfig
	if err := netns.SetListenConfigInterfaceIndex(&lc, tunnelIndex); err != nil {
		logger.Println("Error setting listen config interface index:", err)
		return fmt.Errorf("error setting listen config interface index: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	listener, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		logger.Printf("Error starting server: %v \n", err)
		cancel()
		return err
	}
	go func() {
		acceptLoop(ctx, listener, handleConnection)
		logger.Println("Accept loop for main server stopped")
	}()
	log.Printf("Server started on port %d\n", port)

	subscriberListener, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", subscriberPort))
	if err != nil {
		logger.Printf("Error starting subscriber server: %v \n", err)
		cancel()
		return err
	}
	go acceptLoop(ctx, subscriberListener, handleSubscriberConnection)
	log.Printf("Subscriber server started on port %d\n", subscriberPort)

	isRunning = true
	stopChannel = make(chan struct{})
	go func() {
		<-stopChannel
		logger.Println("Shutting down server...")
		cancel() // Cancel context to stop accept loops
		if err := listener.Close(); err != nil {
			logger.Printf("Server Shutdown Failed:%+v", err)
			return
		}
		if err := subscriberListener.Close(); err != nil {
			logger.Printf("Subscriber Server Shutdown Failed:%+v", err)
			return
		}
		logger.Println("Server shutdown gracefully")
	}()
	return nil
}

func acceptLoop(ctx context.Context, listener net.Listener, handler func(net.Conn)) {
	logger.Printf("Starting accept loop for %v\n", listener.Addr())
	for {
		select {
		case <-ctx.Done():
			logger.Printf("Stopping accept loop for %v\n", listener.Addr())
			return
		default:
			logger.Printf("Accepting connection on %v\n", listener.Addr())
			conn, err := listener.Accept()
			from := ""
			if err == nil && conn != nil {
				from = conn.RemoteAddr().String()
			}
			logger.Printf("Accepted connection from %v, err=%v\n", from, err)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					continue // Just a timeout, keep accepting
				}
				if !isRunning {
					logger.Printf("Stopping accept loop for %v\n", listener.Addr())
					return // Server is shutting down
				}
				logger.Printf("Error accepting connection: %v\n", err)
				continue
			}
			logger.Printf("Accepted connection from %v\n", conn.RemoteAddr())
			go handler(conn)
		}
	}
}
func Stop() {
    logger.Println("Stopping the service")
    wantRunning = false
    if !isRunning {
        logger.Println("Service is not running. Nothing to stop")
        return
    }
	isRunning = false
    close(stopChannel)

    // Create local copies of connections to close
    var connsToClose []net.Conn
    var subsToClose []net.Conn
    var subStopChannels []chan struct{}

    // Get subscribers to close
    subscriberMutex.Lock()
    for conn, stopCh := range subscribers {
        subsToClose = append(subsToClose, conn)
        subStopChannels = append(subStopChannels, stopCh)
    }
    subscriberMutex.Unlock()
	log.Printf("Collected %d subscribers to close\n", len(subsToClose))

    // Get connections to close
    connectionMutex.Lock()
    for conn := range connections {
        connsToClose = append(connsToClose, conn)
    }
    connectionMutex.Unlock()
	log.Printf("Collected %d connections to close\n", len(connsToClose))

    // Close all subscribers
    for i, conn := range subsToClose {
        subStopChannels[i] <- struct{}{}
        conn.Close()
    }
	logger.Println("All subscribers closed")

    // Close all connections
    for _, conn := range connsToClose {
        conn.Close()
    }
	logger.Println("All connections closed")

    // Clear the maps after all connections are closed
    subscriberMutex.Lock()
    subscribers = make(map[net.Conn](chan struct{}))
    subscriberMutex.Unlock()
	logger.Println("All subscribers cleared")

    connectionMutex.Lock()
    connections = make(map[net.Conn]struct{})
    connectionMutex.Unlock()
	logger.Println("All connections cleared")
}

func messageShortString(message string) string {
	if len(message) <= 256 {
		return message
	}
	return message[:256] + "..."
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	connectionMutex.Lock()
	connections[conn] = struct{}{}
	connectionMutex.Unlock()
	defer deleteConnection(conn)

	remote := conn.RemoteAddr()
	logger.Println("New client connected", remote)
	input := bufio.NewReaderSize(conn, fileBufferSize)
	output := bufio.NewWriter(conn)

	var err error
	var fullBuffer []byte
	readBuffer := make([]byte, fileBufferSize)
	logger.Println("Starting to message loop for connection", remote)
	for {
		m := bytes.IndexAny(fullBuffer, "\n")
		if m >= 0 {
			// Got one message. Handle the message.
			message := string(fullBuffer[:m])
			fullBuffer = fullBuffer[m+1:] // Skip the '\n'
			logger.Printf("m=%v len(fullBuffer)=%v\n", m, len(fullBuffer))
			parts := strings.Split(message, ":")
			if len(parts) < 2 {
				logger.Println("Invalid message format:", message)
				break
			}

			id := parts[1]
			fullBuffer, err = handleMessage(input, output, message, fullBuffer)
			if err != nil {
				logger.Println("Error handling message:", err)
				break
			}
			logger.Println("DONE handling one message:", messageShortString(message))
			if _, err := output.Write([]byte("ACK:" + id + ":DONE\n")); err != nil {
				logger.Println("Failed to write ACK:", err)
				break
			}
			output.Flush()
			continue
		}
		logger.Println("Reading from remote", remote, "...")
		n, err := input.Read(readBuffer)
		if err != nil {
			if err != io.EOF {
				logger.Printf("Error reading message: err=%v", err)
			} else {
				logger.Printf("EOF received. This is unexpected. err=%v", err)
			}
			break
		}
		if n <= 0 {
			// No error but no bytes read? Not expected.
			logger.Println("Empty read without error. Unexpected. Close.")
			break
		}
		fullBuffer = append(fullBuffer, readBuffer[:n]...)
	}
	logger.Printf("Done with client %v\n", remote)
}

func deleteSubscriber(conn net.Conn) {
	logger.Println("Deleting subscriber from", conn.RemoteAddr())
	subscriberMutex.Lock()
	delete(subscribers, conn)
	subscriberMutex.Unlock()
	logger.Println("Subscriber deleted", conn.RemoteAddr())
}

func deleteConnection(conn net.Conn) {
	logger.Println("Deleting connection from", conn.RemoteAddr())
	connectionMutex.Lock()
	delete(connections, conn)
	connectionMutex.Unlock()
	logger.Println("Connection deleted", conn.RemoteAddr())
}

func isLocalConnection(local, remote net.Addr) bool {
	localTCP, ok := local.(*net.TCPAddr)
	if !ok {
		logger.Printf("Local address is not TCP: %v\n", local)
		return false
	}

	remoteTCP, ok := remote.(*net.TCPAddr)
	if !ok {
		logger.Printf("Remote address is not TCP: %v\n", remote)
		return false
	}

	// Check if they're on the same interface
	if localTCP.IP.IsUnspecified() {
		// If we're listening on 0.0.0.0 or ::, check if remote is localhost
		return remoteTCP.IP.IsLoopback() || remoteTCP.IP.Equal(localTCP.IP)
	}

	return remoteTCP.IP.Equal(localTCP.IP)
}

func handleSubscriberConnection(conn net.Conn) {
	defer conn.Close()
	local := conn.LocalAddr()
	remote := conn.RemoteAddr()

	// Check if remote address is from the same interface as local
	if !isLocalConnection(local, remote) {
		logger.Printf("Rejecting non-local subscriber connection from %v\n", remote)
		return
	}

	logger.Printf("New subscriber connected %v -> %v\n", remote, local)

	if err := sendBufferedMessages(conn); err != nil {
		logger.Println("Closing subscriber connection", remote, "due to err:", err)
		return
	}

	stopCh := make(chan struct{})
	subscriberMutex.Lock()
	subscribers[conn] = stopCh
	subscriberMutex.Unlock()
	defer deleteSubscriber(conn)
	for {
		select {
		case <-stopCh:
			logger.Println("Stopping signal received. Closing", remote)
			return
		default:
			// Read from the connection with a timeout
			conn.SetReadDeadline(time.Now().Add(time.Second)) // Set a timeout to prevent blocking
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
					continue // Timeout occurred, continue reading
				}
				logger.Printf("Error reading from subscriber %v: %v\n", remote, err)
				return
			}
			if n > 0 {
				logger.Printf("Received from %v: '%v'\n", remote, string(buf[:n]))
			}
		}
	}
}

const (
	fileStartPrefix = "FILE_START:"
)

func handleMessage(input *bufio.Reader, output *bufio.Writer, message string, fullBuffer []byte) ([]byte, error) {
	message = strings.TrimSuffix(message, "\n")
	logger.Println("Received message:", messageShortString(message))
	switch {
	case strings.HasPrefix(message, "TEXT:") || strings.HasPrefix(message, "CTRL:"):
		broadcastOrBufferMessage(message)
	case strings.HasPrefix(message, fileStartPrefix):
		return handleFileTransfer(input, output, message[len(fileStartPrefix):], fullBuffer)
	case strings.HasPrefix(message, "PING"):
		logger.Println("Got ping message")
		// TODO: respond with Pong
	default:
		logger.Printf("Unrecognized message type: '%v'\n", message)
	}
	return fullBuffer, nil
}

func handleFileTransfer(input *bufio.Reader, output *bufio.Writer, startMessage string, fullBuffer []byte) ([]byte, error) {
	parts := strings.Split(startMessage, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid file start message format: %v", startMessage)
	}

	id := parts[0]
	fileName := parts[1]
	fileSize, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid file size %v: %w", fileSize, err)
	}
	logger.Printf("File transfer name: %s size: %d \n", fileName, fileSize)

	filePath := filepath.Join(cacheDir, fileName)
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file %v: %w", filePath, err)
	}
	defer file.Close()

	var (
		extra    []byte
		received int64 = 0
		buffer         = make([]byte, fileBufferSize)
		writer         = bufio.NewWriterSize(file, fileBufferSize)
	)
	defer writer.Flush()

	logger.Println("File created. Starting receiving file.")
	now := time.Now()
	start := now
	alreadyRead := len(fullBuffer)
	if int64(alreadyRead) >= fileSize {
		_, err = writer.Write(fullBuffer[:fileSize])
		if err != nil {
			return nil, fmt.Errorf("failed to write to file: %w", err)
		}
		return fullBuffer[int(fileSize):], nil
	}
	if alreadyRead > 0 {
		_, err = writer.Write(fullBuffer)
		if err != nil {
			return nil, fmt.Errorf("failed to write to file %w", err)
		}
		fullBuffer = nil
		received = int64(alreadyRead)
	}

	ack := time.Now().Add(ackInterval)
	for received < fileSize {
		//logger.Printf("Received=%v filesize=%v\n", received, fileSize)
		n, err := input.Read(buffer)
		if err != nil {
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				continue // Timeout occurred, continue reading
			}
			if err != io.EOF {
				return nil, fmt.Errorf("failed to read from socket: received=%v: %w", received, err)
			}
			if received < fileSize {
				return nil, fmt.Errorf("received EOF before finishing received=%v n=%v", received, n)
			}
			logger.Println("EOF received. Finish file receiving. n=", n)
			break
		}
		//logger.Println("Read:", n)
		now := time.Now()
		if now.After(ack) {
			ack = now.Add(ackInterval)
			if _, err := output.Write([]byte(fmt.Sprintf("ACK:%v:%v\n", id, received))); err != nil {
				return nil, fmt.Errorf("failed to write ack: %w", err)
			}
			logger.Printf("File received %d out of %d\n", received, fileSize)
			go output.Flush()
		}
		if int64(n)+received > fileSize {
			m := int(fileSize - received)
			extra = buffer[m:n]
			n = m
		}
		_, err = writer.Write(buffer[:n])
		if err != nil {
			return nil, fmt.Errorf("failed to write to file: %w", err)
		}
		received += int64(n)
		if received == fileSize {
			logger.Printf("File received all out of %d\n", fileSize)
			break
		} else {
			//logger.Printf("File received %d out of %d\n", received, fileSize)
		}
	}

	delta := time.Since(start).Milliseconds()
	logger.Printf("Completed file receiving in %v ms. Notify APP\n", delta)
	broadcastOrBufferMessage("FILE_END:" + id + ":" + filePath)
	return extra, nil
}

func broadcastMessage(message string) {
	if len(subscribers) <= 0 {
		return
	}
	logger.Println("There are subscribers. Broadcasting message", messageShortString(message))
	for conn, stopCh := range subscribers {
		_, err := conn.Write([]byte(message + "\n"))
		if err != nil {
			logger.Printf("Error writing to subscriber socket %v: %v\n", conn.RemoteAddr(), err)
			stopCh <- struct{}{}
			continue
		}
		logger.Println("Message sent to", conn.RemoteAddr())
	}

}

func broadcastOrBufferMessage(message string) {
	if len(subscribers) > 0 {
		broadcastMessage(message)
	} else {
		notifyTailchatApp("New Message")
		logger.Println("No subscriber, buffering message", messageShortString(message))
		bufferMutex.Lock()
		appendMessagesToBufferFileLocked([]string{message})
		bufferMutex.Unlock()
	}
}

func sendBufferedMessages(conn net.Conn) error {
	remote := conn.RemoteAddr()
	messages := loadBufferedMessages()
	var failedMessages []string
	for index, message := range messages {
		_, err := conn.Write([]byte(message + "\n"))
		if err != nil {
			logger.Printf("Error sending buffered message to %v: %v, message=%s\n", remote, err, message)
			failedMessages = messages[index:]
			break
		}
		logger.Println("Sending buffered message to", remote, messageShortString(message))
	}
	bufferMutex.Lock()
	defer bufferMutex.Unlock()
	clearBufferFileLocked()
	appendMessagesToBufferFileLocked(failedMessages)
	if len(failedMessages) > 0 {
		return fmt.Errorf("failed to send buffered messages to %v failed=%v", remote, len(failedMessages))
	}
	return nil
}

func loadBufferedMessages() []string {
	var messages []string
	_, err := os.Stat(bufferFilePath)
	if os.IsNotExist(err) {
		logger.Println("Buffered messages file not found")
		return messages
	}
	file, err := os.Open(bufferFilePath)
	if err != nil {
		logger.Println("Error opening buffered message file", err)
		return messages
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		messages = append(messages, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		logger.Println("Error reading buffered messages file :", err)
		return []string{}
	}
	logger.Println("Buffered messages loaded successfully")
	return messages

}
func appendMessagesToBufferFileLocked(messages []string) {
	file, err := os.OpenFile(bufferFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Println("Error opening buffer file:", err)
		return
	}
	defer file.Close()
	for _, message := range messages {
		_, err = file.WriteString(message + "\n")
		if err != nil {
			logger.Println("Error writing to buffer file:", err)
		}
	}
	logger.Println("Buffered messages saved successfully")
}

func clearBufferFileLocked() {
	err := os.Truncate(bufferFilePath, 0)
	if err != nil {
		logger.Println("Error truncating buffered message file:", err)
		return
	}
	logger.Println("Buffered messages cleared")
}

func notifyTailchatApp(message string) {
	notifyTailchatAppFunc(message)
}

func SetNotifyTailchatAppFunc(f func(string)) {
	notifyTailchatAppFunc = f
}