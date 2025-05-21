// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailchat

import (
	"bufio"
	"bytes"
	"context"
	"errors"
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

type socketChans struct {
	ackChan  chan string // message ID
	errChan  chan error
	stopChan chan struct{}
}

var (
	bufferMutex     = &sync.Mutex{}
	wantRunning     = false
	isRunning       = false
	logger          = log.New(os.Stdout, "tailchat: ", log.LstdFlags)
	stopChannel     = make(chan struct{})
	subscribers     = make(map[net.Conn]socketChans)
	connections     = make(map[net.Conn]struct{})
	connectionMutex = &sync.RWMutex{}
	subscriberMutex = &sync.RWMutex{}
	cacheDir        string
	bufferFilePath  string
	tunnelIndex     = -1
	startArgs       StartArgs

	errInvalidMessageFormat = fmt.Errorf("invalid message format")

	// notifyTailchatAppFunc is a function to notify the Tailchat app
	notifyTailchatAppFunc = func(Notify) {}
)

// Message passed among functions are without the trailing '\n'
type StartArgs struct {
	Port           int
	SubscriberPort int
	CacheDir       string
}

const (
	ChatReceived           = "CHAT_RECEIVED"
	ChatStatusOK           = "CHAT_STATUS_OK"
	ChatStatusError        = "CHAT_STATUS_ERROR"
	ChatSendBufferredOK    = "CHAT_SEND_BUFFERRED_OK"
	ChatSendBufferredError = "CHAT_SEND_BUFFERRED_ERROR"
)

type Notify struct {
	Event   string
	Message string
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

	go manageAcceptLoop(ctx, "main", port, lc, handleConnection)
	go manageAcceptLoop(ctx, "subscriber", subscriberPort, lc, handleSubscriberConnection)

	isRunning = true
	stopChannel = make(chan struct{})
	go func() {
		<-stopChannel
		logger.Println("Shutting down server...")
		cancel() // Cancel context to stop accept loops
		logger.Println("Server shutdown gracefully")
	}()
	return nil
}

func manageAcceptLoop(ctx context.Context, name string, port int, lc net.ListenConfig, handler func(net.Conn)) {
	backoff := time.Second
	maxBackoff := time.Second * 30

	for wantRunning {
		listener, err := lc.Listen(ctx, "tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			logger.Printf("Error creating listener %v: %v\n", name, err)
			notifyTailchatApp(ChatStatusError, "Error creating listener: "+err.Error())
			time.Sleep(backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		notifyTailchatApp(ChatStatusOK, "Listener created on port "+strconv.Itoa(port))
		logger.Printf("Started %s listener on port %d\n", name, port)
		backoff = time.Second // Reset backoff on successful listener creation

		// Run accept loop until error
		if err := acceptLoop(ctx, listener, handler); err != nil {
			logger.Printf("%s accept loop failed: %v\n", name, err)
			listener.Close()

			if !wantRunning {
				return
			}

			time.Sleep(backoff)
			backoff = min(backoff*2, maxBackoff)
		}
	}
}

func acceptLoop(ctx context.Context, listener net.Listener, handler func(net.Conn)) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled")
		default:
			conn, err := listener.Accept()
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					continue
				}
				// Return error to trigger listener recreation
				return fmt.Errorf("accept failed: %w", err)
			}

			if conn != nil {
				logger.Printf("Accepted connection from %v\n", conn.RemoteAddr())
				go handler(conn)
			}
		}
	}
}

// Helper function for time.Duration comparison
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
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
	for conn, chans := range subscribers {
		subsToClose = append(subsToClose, conn)
		subStopChannels = append(subStopChannels, chans.stopChan)
	}
	subscriberMutex.Unlock()
	logger.Printf("Collected %d subscribers to close\n", len(subsToClose))

	// Get connections to close
	connectionMutex.Lock()
	for conn := range connections {
		connsToClose = append(connsToClose, conn)
	}
	connectionMutex.Unlock()
	logger.Printf("Collected %d connections to close\n", len(connsToClose))

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
	subscribers = make(map[net.Conn]socketChans)
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
	local := conn.LocalAddr()
	remote := conn.RemoteAddr()

	// Check if remote address is from the same interface as local
	if !isLocalConnection(local, remote) {
		logger.Printf("Rejecting non-local subscriber connection from %v\n", remote)
		conn.Close()
		return
	}

	logger.Printf("New subscriber connected %v -> %v\n", remote, local)
	var (
		stopCh  = make(chan struct{})
		ackChan = make(chan string, 1)
		errChan = make(chan error, 1)
	)
	subscriberMutex.Lock()
	subscribers[conn] = socketChans{
		stopChan: stopCh,
		ackChan:  ackChan,
		errChan:  errChan,
	}
	subscriberMutex.Unlock()
	go func() {
		defer func() {
			logger.Printf("Subscriber connection %v DONE. Closing the connection.", remote)
			conn.Close()
			deleteSubscriber(conn)
		}()
		buffer := make([]byte, 1024)
		fullBuffer := make([]byte, 0)
		for {
			select {
			case <-stopCh:
				logger.Println("Stopping signal received. Closing subscriber", remote)
				return
			default:
				// Read from the connection with a timeout
				logger.Printf("Waiting for ACK from subscriber %v\n", remote)
				conn.SetReadDeadline(time.Now().Add(ackTimeout)) // Set a timeout to prevent blocking
				n, err := conn.Read(buffer)
				if err != nil {
					if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
						continue // Timeout occurred, continue reading
					}
					errChan <- fmt.Errorf("error reading subscriber conn %v: %v", remote, err)
					logger.Printf("Error reading from subscriber %v: %v\n", remote, err)
					return
				}
				fullBuffer = append(fullBuffer, buffer[:n]...)
				for {
					m := bytes.IndexAny(fullBuffer, "\n")
					if m < 0 {
						break // No complete message yet
					}
					// Got one message. Handle the message.
					message := string(fullBuffer[:m])
					fullBuffer = fullBuffer[m+1:] // Skip the '\n'
					logger.Printf("m=%v len(fullBuffer)=%v\n", m, len(fullBuffer))
					response := strings.TrimSpace(message)
					parts := strings.Split(response, ":")
					if len(parts) == 3 && parts[0] == "ACK" && parts[1] != "" && parts[2] == "DONE" {
						logger.Printf("Received ACK from subscriber %v: %s\n", remote, response)
						ackChan <- parts[1]
					} else {
						logger.Printf("Invalid ACK format from %v: %s\n", remote, response)
						errChan <- fmt.Errorf("invalid ACK format from %v: %s", remote, response)
					}
				}
			}
		}
	}()

	if err := sendBufferedMessages(conn, ackChan, errChan); err != nil {
		logger.Println("Closing subscriber connection", remote, "due to err:", err)
		stopCh <- struct{}{}
		notifyTailchatApp(ChatSendBufferredError, "Error sending buffered messages to "+remote.String())
		return
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
		return fullBuffer, broadcastOrBufferMessage(message)
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
	if err := broadcastOrBufferMessage("FILE_END:" + id + ":" + filePath); err != nil {
		return nil, fmt.Errorf("failed to broadcast file end message: %w", err)
	}
	return extra, nil
}
func broadcastMessage(message string) error {
	if len(subscribers) <= 0 {
		return nil
	}

	messageID := extractMessageID(message)
	if messageID == "" {
		logger.Printf("Invalid message format for broadcast: %s\n", messageShortString(message))
		return errInvalidMessageFormat
	}

	logger.Println("Broadcasting message", messageShortString(message))

	// Create local copy to avoid map changes during iteration
	subscriberMutex.RLock()
	subConns := make(map[net.Conn]socketChans)
	for conn, chans := range subscribers {
		subConns[conn] = chans
	}
	subscriberMutex.RUnlock()

	sent := false
	for conn, chans := range subConns {
		logger.Printf("Sending message to subscriber %v\n", conn.RemoteAddr())
		conn.SetReadDeadline(time.Now().Add(ackTimeout))
		_, err := conn.Write([]byte(message + "\n"))
		if err != nil {
			logger.Printf("Error writing to subscriber %v: %v\n", conn.RemoteAddr(), err)
			close(chans.stopChan)
			continue
		}

		// Wait for ACK with timeout
		if err := waitForAck(conn, messageID, chans.ackChan, chans.errChan); err != nil {
			close(chans.stopChan)
			continue
		}
		logger.Printf("ACK received for broadcast message %s from %v\n", messageID, conn.RemoteAddr())
		sent = true
	}
	if !sent {
		logger.Println("No subscribers available for broadcast message", messageShortString(message))
		return fmt.Errorf("no subscribers available for broadcast message %s", messageID)
	}
	return nil
}

// Wait for ACK with timeout
func waitForAck(conn net.Conn, messageID string, ackChan chan string, errChan chan error) error {
	select {
	case <-errChan:
	default:
	}
	for {
		select {
		case id := <-ackChan:
			if id != messageID {
				logger.Printf("Received ACK for different message %s from %v\n", id, conn.RemoteAddr())
				continue
			}
			logger.Printf("Received ACK for broadcast message %s from %v\n", messageID, conn.RemoteAddr())
			return nil
		case err := <-errChan:
			logger.Printf("Failed to get ACK from %v: %v\n", conn.RemoteAddr(), err)
			return err
		case <-time.After(ackTimeout):
			logger.Printf("ACK timeout for broadcast message %s from %v\n", messageID, conn.RemoteAddr())
			return fmt.Errorf("ACK timeout for message %s from %v", messageID, conn.RemoteAddr())
		}
	}
}

func broadcastOrBufferMessage(message string) error {
	if len(subscribers) > 0 {
		err := broadcastMessage(message)
		if err == nil {
			return nil
		}
		if errors.Is(err, errInvalidMessageFormat) {
			return err
		}
		// Fallback to buffering if broadcast fails
	}
	notifyTailchatApp(ChatReceived, "New Message")
	logger.Println("No subscriber or broadcastting failed, buffering message", messageShortString(message))
	bufferMutex.Lock()
	err := appendMessagesToBufferFileLocked([]string{message})
	bufferMutex.Unlock()
	return err
}

const ackTimeout = time.Second * 5 // Timeout for waiting for ACK

func extractMessageID(message string) string {
	parts := strings.Split(message, ":")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}
func sendBufferedMessages(conn net.Conn, ackChan chan string, errChan chan error) error {
	remote := conn.RemoteAddr()
	messages := loadBufferedMessages()
	if len(messages) == 0 {
		logger.Println("No buffered messages to send to", remote)
		return nil
	}

	var failedMessages []string

	for index, message := range messages {
		messageID := extractMessageID(message)
		if messageID == "" {
			err := fmt.Errorf("invalid message format: %s", messageShortString(message))
			logger.Printf("Error: %v\n", err)
			failedMessages = messages[index:]
			break
		}

		// Send message
		conn.SetReadDeadline(time.Now().Add(ackTimeout))
		_, err := conn.Write([]byte(message + "\n"))
		if err != nil {
			logger.Printf("Error sending message to subscriber %v: %v\n", remote, err)
			failedMessages = messages[index:]
			break
		}

		if err := waitForAck(conn, messageID, ackChan, errChan); err != nil {
			logger.Printf("Error waiting for ACK for message %s from %v: %v\n", messageID, remote, err)
			failedMessages = messages[index:]
			break
		}
	}

	// Update buffer file with remaining messages
	bufferMutex.Lock()
	defer bufferMutex.Unlock()
	clearBufferFileLocked()
	if len(failedMessages) > 0 {
		appendMessagesToBufferFileLocked(failedMessages)
		return fmt.Errorf("failed to send messages to %v, %d messages remaining",
			remote, len(failedMessages))
	}

	notifyTailchatApp(ChatSendBufferredOK,
		fmt.Sprintf("%v buffered messages sent to %v", len(messages), remote))
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
func appendMessagesToBufferFileLocked(messages []string) error {
	file, err := os.OpenFile(bufferFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Println("Error opening buffer file:", err)
		return err
	}
	defer file.Close()
	for _, message := range messages {
		_, err = file.WriteString(message + "\n")
		if err != nil {
			logger.Println("Error writing to buffer file:", err)
			return err
		}
	}
	logger.Println("Buffered messages saved successfully")
	return nil
}

func clearBufferFileLocked() {
	err := os.Truncate(bufferFilePath, 0)
	if err != nil {
		logger.Println("Error truncating buffered message file:", err)
		return
	}
	logger.Println("Buffered messages cleared")
}

func notifyTailchatApp(event, message string) {
	notifyTailchatAppFunc(Notify{
		Event:   event,
		Message: message,
	})
}

func SetNotifyTailchatAppFunc(f func(Notify)) {
	notifyTailchatAppFunc = f
}
