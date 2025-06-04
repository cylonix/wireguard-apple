package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/apple/libtailscale"
	"golang.zx2c4.com/wireguard/apple/tailchat"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/types/logger"
	"tailscale.com/version"
)

const (
	dashs = "__________________________"

	alwaysUseRelayEnabledStateKey = ipn.StateKey("_always_use_relay_enabled")
	tailchatStateKey              = ipn.StateKey("_tailchat")

	sendFilesToPeerCmd = "send_files_to_peer"
)

var (
	app                   libtailscale.Application
	cachedNetworkSettings *NetworkSettings
	clogf                 = logger.WithPrefix(CLogger(0).Printf, "[Cylonix]: ")
	cylonixInitDone       = false
	fileWatingManager     libtailscale.NotificationManager
	notifyManager         libtailscale.NotificationManager
	savedTunFd            int32 = -1
	service               *ipnService
	store                 *stateStore

	errKeychainItemNotFound = errors.New("keychain item not found")
)

func initCylonixBackend(tunFd int32) int32 {
	if !cylonixInitDone {
		cylonixInitDone = true
		if err := cylonixInit(); err != nil {
			clogf("Cylonix init failed: %v", err)
			return -1
		}
	}
	if savedTunFd != -1 {
		if savedTunFd == tunFd {
			clogf("Same as the saved fd. Skip update")
			return 0
		}
		clogf("Saved fd=%v. Cannot handle this", savedTunFd)
		return -1
	}
	go func() {
		clogf("Requesting to start VPN")
		requestVPN(int32(tunFd))
		clogf("Requested to start VPN")
	}()
	savedTunFd = tunFd
	return 0
}

func cylonixVersion() string {
	return "Cylonix " + version.Long()
}

func filesWaiting(message string) {
	if _, err := callWgAdapter("filesWaiting", message); err != nil {
		clogf("Failed to notify files waiting: %v", err)
	}
}

func chatsReceived(message string) {
	if _, err := callWgAdapter("chatsReceived", message); err != nil {
		clogf("Failed to notify chats received: %v", err)
	}
}

func chatStatus(message string) {
	if _, err := callWgAdapter("chatStatus", message); err != nil {
		clogf("Failed to notify chat status: %v", err)
	}
}

func ipnNotify(message string) error {
	if _, err := callWgAdapter("ipnNotify", message); err != nil {
		clogf("Failed to notify ipn: %v", err)
		return fmt.Errorf("failed to notify ipn: %v", err)
	}
	return nil
}
func setNetworkSettings(settings NetworkSettings) error {
	jsonBytes, err := json.Marshal(settings)
	if err != nil {
		clogf("Failed to marshal network settings %v", err)
		return fmt.Errorf("failed to marshal network settings: %v", err)
	}
	j, err := json.MarshalIndent(settings, "", "\t")
	clogf("Sending network settings %v, err: %v", string(j), err)

	v, err := callWgAdapter("setNetworkSettings", string(jsonBytes))
	if err != nil {
		clogf("Failed to set network settings: %v", err)
		return fmt.Errorf("failed to set network settings: %v", err)
	}
	clogf("Set network settings done: %v bytes: ret=%q", len(jsonBytes), string(v))
	return nil
}

func setKeychainItem(key, val string) error {
	if _, err := callWgAdapter("setKeychainItem", key+" "+val); err != nil {
		clogf("Failed to set keychain @%q: %v", key, err)
		return fmt.Errorf("failed to set keychain: %v", err)
	}
	clogf("Set keychain @%q=%q success", key, shortString(val))
	return nil
}

func getKeychainItem(key string) ([]byte, error) {
	v, err := callWgAdapter("getKeychainItem", key)
	if err == nil && string(v) == "keychain item not found" {
		clogf("Keychain @%q not found", key)
		return nil, errKeychainItemNotFound
	}
	if err != nil {
		clogf("Failed to get keychain @%v: %v", key, err)
		return nil, fmt.Errorf("failed to get keychain: %w", err)
	}
	clogf("Get keychain @%q success: %q", key, shortString(string(v)))
	return v, nil
}

func getTunnelFileDescriptor() (int32, error) {
	return savedTunFd, nil
}

func getSharedAppGroupDir() (string, error) {
	clogf("%v getSharedAppGroupDir %v", dashs, dashs)
	if groupFolder == "" {
		return "", fmt.Errorf("container path not set")
	}

	// Ensure directory exists
	err := os.MkdirAll(groupFolder, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create app group directory: %w", err)
	}

	return groupFolder, nil
}

func setAlwaysUseRelay() {
	envknob.Setenv("TS_DEBUG_ALWAYS_USE_DERP", "1")
}

func cylonixInit() error {
	clogf("%v Cylonix Init %v", dashs, dashs)
	dataDir, err := getSharedAppGroupDir()
	if err != nil {
		return fmt.Errorf("failed to get shared app group dir: %w", err)
	}
	if notifyManager != nil {
		notifyManager.Stop()
		notifyManager = nil
	}
	if fileWatingManager != nil {
		fileWatingManager.Stop()
		fileWatingManager = nil
	}
	a := &CylonixAppCtx{store: store}

	// Set up debug logging before anything else
	debugLogPath := dataDir + "/cylonixd_debug.log"
	clogf("attempting to set log output to: %v", debugLogPath)

	// First verify we can access the directory
	if err := os.MkdirAll(filepath.Dir(debugLogPath), 0755); err != nil {
		return fmt.Errorf("failed to create debug log directory: %w", err)
	}

	// Try opening the file with error handling
	f, err := os.OpenFile(debugLogPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open debug log file: %w", err)
	}
	f.Truncate(0)   // Clear the file
	defer f.Close() // Ensure file is closed even if we panic

	// Create a buffered writer to reduce I/O operations
	bufWriter := bufio.NewWriter(f)
	writer := io.MultiWriter(os.Stderr, bufWriter)

	// Ensure buffer is flushed on exit
	defer func() {
		if bufWriter != nil {
			bufWriter.Flush()
		}
	}()

	// Set log output with safer handling
	if err := setLogOutput(writer); err != nil {
		return fmt.Errorf("failed to set log output: %w", err)
	}

	// Verify logging is working
	clogf("Log output successfully initialized")
	clogf("%v dataDir: %v %v", dashs, dataDir, dashs)
	store = newStateStore()
	clogf("%v starting libtailscale %v", dashs, dashs)
	tailDropDir, err := getPlatformTailDropDir()
	if err != nil {
		return fmt.Errorf("failed to get platform taildrop dir: %w", err)
	}

	// Check to enable tailchat
	v, err := store.ReadState(tailchatStateKey)
	if err != nil && !errors.Is(err, ipn.ErrStateNotExist) {
		return fmt.Errorf("failed to get tailchat enabled state: %w", err)
	}
	if len(v) > 0 {
		clogf("tailchat is enabled")
		startArgs := tailchat.StartArgs{}
		if err := json.Unmarshal(v, &startArgs); err != nil {
			return fmt.Errorf("failed to parse tailchat start args: %w", err)
		}
		if err := tailchat.Start(startArgs); err != nil {
			return fmt.Errorf("failed to start tailchat: %w", err)
		}
	}
	// Check to enable always use relay
	alwaysUseRelayEnabledStateKey, err := store.GetBoolState(alwaysUseRelayEnabledStateKey)
	if err != nil {
		return fmt.Errorf("failed to get always use relay enabled state: %w", err)
	}
	if alwaysUseRelayEnabledStateKey {
		clogf("always use relay is enabled")
		setAlwaysUseRelay()
	} else {
		clogf("always use relay is not enabled")
	}

	app = libtailscale.Start(dataDir, tailDropDir, a)
	go func() {
		clogf("Start watching for notifications")
		notifyManager = app.WatchNotifications(notificationMarsk(), &notificationCallback{})
		if fileWatingManager != nil {
			clogf("FileWatingManager is not nil. This is not expected. Stopping it")
			fileWatingManager.Stop()
		}
		fileWatingManager = app.WatchAwaitingFiles(handleFilesWaiting)
	}()
	clogf("%v libtailscale started %v", dashs, dashs)
	return nil
}

type FilesWaiting struct {
	Dir   string
	Files []apitype.WaitingFile
}

func handleFilesWaiting(dir string, files []apitype.WaitingFile) {
	if files == nil {
		clogf("no files waiting")
	}
	// Notify Swift code about files waiting
	v, err := json.Marshal(&FilesWaiting{Dir: dir, Files: files})
	if err != nil {
		clogf("failed to marshal files waiting: %v", err)
		return
	}
	filesWaiting(string(v))
}

func getPlatformTailDropDir() (string, error) {
	return "", nil
}

func setLogOutput(writer io.Writer) (err error) {
	// Set up panic recovery before anything else
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			// Log using clogf since it's our safe logging function
			clogf("PANIC in setLogOutput: %v\nStack:\n%s", r, stack)
			err = fmt.Errorf("panic in setLogOutput: %v", r)
		}
	}()

	// Create a safe wrapped writer that won't panic
	safeWriter := &safeWriter{w: writer}

	// Set the log output in a separate function to ensure defer works
	log.SetOutput(safeWriter)

	return nil
}

// safeWriter wraps an io.Writer with panic recovery
type safeWriter struct {
	w io.Writer
}

func (sw *safeWriter) Write(p []byte) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in Write: %v", r)
		}
	}()
	sw.w.Write([]byte("safeWriter: "))
	return sw.w.Write(p)
}

func shortString(s string) string {
	a := s
	if len(s) > 16 {
		a = a[:16] + "..."
	}
	return a
}

func TryCatch(f func()) func() error {
	return func() (err error) {
		defer func() {
			if panicInfo := recover(); panicInfo != nil {
				err = fmt.Errorf("%v, %s", panicInfo, string(debug.Stack()))
				return
			}
		}()
		f() // calling the decorated function
		return err
	}
}

func TryCatchLoop(f func()) func() {
	return func() {
		for {
			if err := TryCatch(f)(); err != nil {
				fmt.Println(err)
			} else {
				return
			}
		}
	}
}

// CylonixAppCtx implements libtailscale.AppContext
type CylonixAppCtx struct {
	store *stateStore
}

func (c *CylonixAppCtx) Log(tag, logLine string) {
	CLogger(0).Printf("[%s]: %s", tag, logLine)
}

func (c *CylonixAppCtx) EncryptToPref(key, value string) error {
	err := c.store.write(key, []byte(value))
	if err != nil {
		clogf("Failed to write key: %v", key)
	}
	return err
}

func (c *CylonixAppCtx) DecryptFromPref(key string) (string, error) {
	data, err := c.store.read(key)
	if err != nil {
		clogf("Failed to read key: %v", key)
		return "", err
	}
	return string(data), nil
}

func (c *CylonixAppCtx) GetOSVersion() (string, error) {
	return systemInfo.OSVersion, nil
}

func (c *CylonixAppCtx) GetModelName() (string, error) {
	return systemInfo.DeviceModel, nil
}

// Helper function to map hardware model identifiers to marketing names
func getDeviceMarketingName(model string) string {
	deviceMap := map[string]string{
		"iPhone14,2": "iPhone 13 Pro",
		"iPhone14,3": "iPhone 13 Pro Max",
		"iPhone14,4": "iPhone 13 mini",
		"iPhone14,5": "iPhone 13",
		"iPhone15,2": "iPhone 14 Pro",
		"iPhone15,3": "iPhone 14 Pro Max",
		"iPhone15,4": "iPhone 14",
		"iPhone15,5": "iPhone 14 Plus",
		"iPhone16,1": "iPhone 15 Pro",
		"iPhone16,2": "iPhone 15 Pro Max",
		"iPhone16,3": "iPhone 15",
		"iPhone16,4": "iPhone 15 Plus",
		"iPad13,4":   "iPad Pro 11-inch (3rd generation)",
		"iPad13,8":   "iPad Pro 12.9-inch (5th generation)",
		"iPad13,16":  "iPad Pro 11-inch (4th generation)",
		"iPad13,17":  "iPad Pro 12.9-inch (6th generation)",
		// Add more models as needed
	}

	if name, ok := deviceMap[model]; ok {
		return name
	}
	return ""
}

func (c *CylonixAppCtx) GetInstallSource() string {
	return "appstore"
}

func (c *CylonixAppCtx) IsPlayVersion() bool {
	return false
}

func (c *CylonixAppCtx) ShouldUseGoogleDNSFallback() bool {
	return true
}

func (c *CylonixAppCtx) IsChromeOS() (bool, error) {
	return false, nil
}
func (c *CylonixAppCtx) GetInterfacesAsString() (string, error) {
	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %w", err)
	}

	var lines []string
	for _, iface := range ifaces {
		// Format flags as booleans
		up := (iface.Flags & net.FlagUp) != 0
		broadcast := (iface.Flags & net.FlagBroadcast) != 0
		loopback := (iface.Flags & net.FlagLoopback) != 0
		pointToPoint := (iface.Flags & net.FlagPointToPoint) != 0
		multicast := (iface.Flags & net.FlagMulticast) != 0

		// Format the first part with interface details
		ifaceInfo := fmt.Sprintf("%s %d %d %t %t %t %t %t",
			iface.Name,
			iface.Index,
			iface.MTU,
			up,
			broadcast,
			loopback,
			pointToPoint,
			multicast)

		// Get IP addresses
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// Format addresses
		addrStrings := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addrStrings = append(addrStrings, addr.String())
		}

		// Combine interface info and addresses with the separator
		line := fmt.Sprintf("%s | %s", ifaceInfo, strings.Join(addrStrings, " "))
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n"), nil
}

func (c *CylonixAppCtx) GetPlatformDNSConfig() string {
	log.Println("GetPlatformDNSConfig")
	return ""
}

func (c *CylonixAppCtx) GetSyspolicyStringValue(string) (string, error) {
	return "", nil
}

func (c *CylonixAppCtx) GetSyspolicyBooleanValue(key string) (bool, error) {
	return false, nil
}

func (c *CylonixAppCtx) GetSyspolicyStringArrayJSONValue(key string) (string, error) {
	return "", nil
}

func (c *CylonixAppCtx) TunnelUpdated(ifIndex int) {
	tailchat.TunnelUpdated(ifIndex)
}

func (c *CylonixAppCtx) TunnelClearConfig() {
	clearNetworkSettings()
}

func isClientDependantCmd(cmd string) bool {
	switch cmd {
	case "start_tailchat", "stop_tailchat", "is_tailchat_running":
		return false
	case "log", "get_env_knob", "set_env_knobs", "turn_off_vpn":
		return false
	default:
		return true
	}
}

func handleCommand(cmd, args string) string {
	//log.Printf("Received cmd: %v args: %v", cmd, args)
	if app == nil && isClientDependantCmd(cmd) {
		return "App not initialized"
	}
	var client *libtailscale.Client
	if app != nil {
		client = libtailscale.NewClient(app)
	}
	switch cmd {
	case "start":
		err := client.Start(args)
		if err != nil {
			return fmt.Sprintf("Error starting: %v", err)
		}
		return "Success"
	case "start_login_interactive":
		clogf("calling start login interactive local client")
		err := client.StartLoginInteractive()
		if err != nil {
			clogf("start login interface failed: %v", err)
			return fmt.Sprintf("Error starting login interactive: %v", err)
		}
		clogf("start login interactive success")
		return "Success"
	case "edit_prefs":
		err := client.EditPrefs(args)
		if err != nil {
			return fmt.Sprintf("Error editing prefs: %v", err)
		}
		return "Success"
	case "turn_off_vpn":
		clogf("Turn off VPN requested")
		if err := turnOffVPN(); err != nil {
			return fmt.Sprintf("Error turning off VPN: %v", err)
		}
		return "Success"
	case "profiles":
		result := []ipn.LoginProfile{}
		err := client.Profiles(&result)
		if err != nil {
			return fmt.Sprintf("Error getting profiles: %v", err)
		}
		v, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf("Error encoding profiles: %v", err)
		}
		return string(v)
	case "current_profile":
		result := ipn.LoginProfile{}
		err := client.CurrentProfile(&result)
		if err != nil {
			return fmt.Sprintf("Error getting profiles: %v", err)
		}
		v, err := json.Marshal(result)
		if err != nil {
			return fmt.Sprintf("Error encoding profiles: %v", err)
		}
		return string(v)

	case "add_profile":
		err := client.AddProfile()
		if err != nil {
			return fmt.Sprintf("Error add profile: %v", err)
		}
		return "Success"
	case "switch_profile":
		id := ipn.ProfileID(args)
		err := client.SwitchProfile(id)
		if err != nil {
			return fmt.Sprintf("Error switch profile: %v", err)
		}
		return "Success"
	case "ping":
		result, err := client.Ping(args)
		if err != nil {
			return fmt.Sprintf("Error pinging: %v", err)
		}
		return result
	case "start_tailchat":
		tailchat.SetNotifyTailchatAppFunc(func(n tailchat.Notify) {
			if n.Event == tailchat.ChatReceived {
				chatsReceived(n.Message)
			} else {
				v, err := json.Marshal(n)
				if err != nil {
					clogf("Error marshalling tailchat notification: %v", err)
					return
				}
				chatStatus(string(v))
			}
		})
		tailchatStartArgs := &tailchat.StartArgs{}
		if args != "" {
			err := json.Unmarshal([]byte(args), tailchatStartArgs)
			if err != nil {
				return fmt.Sprintf("Error unmarshalling args: %v", err)
			}
		}
		if err := tailchat.Start(*tailchatStartArgs); err != nil {
			return fmt.Sprintf("Error starting tailchat: %v", err)
		}
		v, err := json.Marshal(tailchatStartArgs)
		if err != nil {
			return fmt.Sprintf("Error encoding tailchat args: %v", err)
		}
		if err := store.WriteState(tailchatStateKey, v); err != nil {
			return fmt.Sprintf("Error writing tailchat state: %v", err)
		}
		return "Success"
	case "stop_tailchat":
		tailchat.Stop()
		return "Success"
	case "is_tailchat_running":
		if tailchat.IsRunning() {
			return "true"
		}
		return "false"
	case "status":
		result, err := client.Status()
		if err != nil {
			return fmt.Sprintf("Error getting status: %v", err)
		}
		return result
	case "logout":
		err := client.Logout()
		if err != nil {
			return fmt.Sprintf("Error logging out: %v", err)
		}
		return "Success"
	case "set_env_knobs":
		if args == "" {
			return "Error: no arguments provided"
		}
		kvs, err := parseKeyValue(args)
		if err != nil {
			return fmt.Sprintf("Error parsing arguments: %v", err)
		}
		clogf("Set env knob: %v", kvs)
		for k, v := range kvs {
			envknob.Setenv(k, v)
		}
		// Some env knobs need follow up actions
		if v, ok := kvs["TS_DEBUG_ALWAYS_USE_DERP"]; ok {
			if err := onEnvknobSetAlwaysUseRelay(v, client); err != nil {
				return fmt.Sprintf("Error setting TS_DEBUG_ALWAYS_USE_DERP: %v", err)
			}
			clogf("TS_DEBUG_ALWAYS_USE_DERP set to %v", v)
		}
		return "Success"
	case "get_env_knob":
		if args == "" {
			return "Error: no arguments provided"
		}
		clogf("Get env knob: %v", args)
		return os.Getenv(args)
	case "log":
		log.Println(args)
		return "Success"
	case sendFilesToPeerCmd:
		result := ""
		sendArgs := &SendFilesToPeerArgs{}
		if err := json.Unmarshal([]byte(args), sendArgs); err != nil {
			return fmt.Sprintf("Error unmarshalling args: %v", err)
		}
		if err := client.PutTaildropFiles(sendArgs.PeerID, sendArgs.Files, &result); err != nil {
			return fmt.Sprintf("Error sending files to peer: %v", err)
		}
		return "Success: " + result
	case "watch_notifications":
		log.Println("Starting notification manager")
		if notifyManager != nil {
			log.Println("Stopping previous notification manager")
			notifyManager.Stop()
		}
		notifyManager = app.WatchNotifications(notificationMarsk(), &notificationCallback{})
		if notifyManager == nil {
			return "Error: failed to start notification manager"
		}
		log.Println("Notification manager started successfully")
		return "Success"
	default:
		return fmt.Sprintf("Unknown command: %v", cmd)
	}
}

func onEnvknobSetAlwaysUseRelay(setting string, client *libtailscale.Client) error {
	on, err := strconv.ParseBool(setting)
	if err != nil {
		return fmt.Errorf("failed to parse setting '%q': %w", setting, err)
	}
	if err := store.SetBoolState(alwaysUseRelayEnabledStateKey, on); err != nil {
		return fmt.Errorf("failed to store state: %w", err)
	}
	if client != nil {
		clogf("Rebinding for alwaysUserRelay(%v)", on)
		if err := client.DebugRebind(); err != nil {
			return fmt.Errorf("failed to rebind for alwaysUserRelay(%v): %w", on, err)
		}
		clogf("Rebinding DONE. Re-stunning for alwaysUserRelay(%v)", on)
		if err := client.DebugReStun(); err != nil {
			return fmt.Errorf("failed to restun for alwaysUserRelay(%v): %w", on, err)
		}
		clogf("Re-stunning DONE for alwaysUserRelay(%v)", on)
	}
	return nil
}

func getCmdTimeout(cmd string) time.Duration {
	if cmd == sendFilesToPeerCmd {
		return 24 * time.Hour
	}
	// Default timeout for commands
	return 5 * time.Second
}

type SendFilesToPeerArgs struct {
	PeerID string                      `json:"peer_id"`
	Files  []libtailscale.OutgoingFile `json:"files"`
}

// Helper function to parse key-value string into map
func parseKeyValue(s string) (map[string]string, error) {
	result := make(map[string]string)

	// Handle empty string
	if s == "" {
		return result, nil
	}

	// Try JSON first
	if err := json.Unmarshal([]byte(s), &result); err == nil {
		return result, nil
	}

	// Fallback to key=value format
	pairs := strings.Split(s, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid key-value pair: %s", pair)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		result[key] = value
	}

	return result, nil
}

func notificationMarsk() int {
	// EngineUpdate | Netmap | Prefs | InitialState | InitialHealthState
	return int(
		//ipn.NotifyWatchEngineUpdates |
		ipn.NotifyInitialPrefs |
			ipn.NotifyInitialState |
			ipn.NotifyInitialNetMap |
			ipn.NotifyInitialHealthState)
}

type notificationCallback struct{}

func (n *notificationCallback) OnNotify(data []byte) error {
	return ipnNotify(string(data))
}

// VPNBuilder collects network settings before applying them all at once
type VPNBuilder struct {
	mtu           int32
	addresses     []netip.Prefix
	routes        []netip.Prefix
	excludeRoutes []netip.Prefix
	dnsServers    []string
	searchDomains []string
}

// newVPNBuilder creates a new VPN configuration builder
func newVPNBuilder() *VPNBuilder {
	return &VPNBuilder{
		mtu:           1280, // default MTU
		addresses:     make([]netip.Prefix, 0),
		routes:        make([]netip.Prefix, 0),
		excludeRoutes: make([]netip.Prefix, 0),
		dnsServers:    make([]string, 0),
		searchDomains: make([]string, 0),
	}
}

// SetMTU sets the MTU for the VPN interface
func (b *VPNBuilder) SetMTU(mtu int32) error {
	if mtu < 1280 || mtu > 65535 {
		return fmt.Errorf("invalid MTU %d", mtu)
	}
	b.mtu = mtu
	return nil
}

// AddAddress adds an IP address to the VPN interface
func (b *VPNBuilder) AddAddress(addr string, prefixLength int32) error {
	prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", addr, prefixLength))
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	b.addresses = append(b.addresses, prefix)
	return nil
}

// AddRoute adds a route to be handled by the VPN
func (b *VPNBuilder) AddRoute(addr string, prefixLength int32) error {
	prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", addr, prefixLength))
	if err != nil {
		return fmt.Errorf("invalid route: %w", err)
	}
	b.routes = append(b.routes, prefix)
	return nil
}

// ExcludeRoute adds a route to be excluded from the VPN
func (b *VPNBuilder) ExcludeRoute(addr string, prefixLength int32) error {
	prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", addr, prefixLength))
	if err != nil {
		return fmt.Errorf("invalid exclude route: %w", err)
	}
	b.excludeRoutes = append(b.excludeRoutes, prefix)
	return nil
}

// AddDNSServer adds a DNS server to the VPN configuration
func (b *VPNBuilder) AddDNSServer(server string) error {
	if ip := netip.MustParseAddr(server); !ip.IsValid() {
		return fmt.Errorf("invalid DNS server address: %s", server)
	}
	b.dnsServers = append(b.dnsServers, server)
	return nil
}

// AddSearchDomain adds a DNS search domain
func (b *VPNBuilder) AddSearchDomain(domain string) error {
	b.searchDomains = append(b.searchDomains, domain)
	return nil
}

// Establish applies the configuration and creates the VPN interface
func (b *VPNBuilder) Establish() (libtailscale.ParcelFileDescriptor, error) {
	clogf("Establishing VPN with MTU: %d, Addresses: %v, Routes: %v, ExcludeRoutes: %v, DNSServers: %v, SearchDomains: %v",
		b.mtu, b.addresses, b.routes, b.excludeRoutes, b.dnsServers, b.searchDomains)
	// Convert configuration to NetworkSettings format
	settings := NetworkSettings{
		MTU:           b.mtu,
		Addresses:     b.addresses,
		Routes:        b.routes,
		ExcludeRoutes: b.excludeRoutes,
		DNSServers:    b.dnsServers,
		SearchDomains: b.searchDomains,
	}

	// Call into Swift to apply the settings
	if err := setNetworkSettings(settings); err != nil {
		clogf("Failed to set network settings: %v", err)
		return nil, fmt.Errorf("failed to establish VPN: %w", err)
	}
	clogf("Network settings cached: %#v", settings)
	cachedNetworkSettings = &settings

	// Return a file descriptor for the TUN device
	fd, err := getTunnelFileDescriptor()
	if err != nil {
		clogf("Failed to get tunnel file descriptor: %v", err)
		return nil, fmt.Errorf("failed to get tunnel file descriptor: %w", err)
	}

	clogf("VPN established with file descriptor: %d", fd)
	return &parcelFileDescriptor{fd: fd}, nil
}

type NetworkSettings struct {
	MTU           int32          `json:"mtu"`
	Addresses     []netip.Prefix `json:"addresses"`
	Routes        []netip.Prefix `json:"routes"`
	ExcludeRoutes []netip.Prefix `json:"excludedRoutes"`
	DNSServers    []string       `json:"dnsServers"`
	SearchDomains []string       `json:"searchDomains"`
}

// parcelFileDescriptor implements ParcelFileDescriptor
type parcelFileDescriptor struct {
	fd int32
}

func (p *parcelFileDescriptor) Detach() (int32, error) {
	dupTunFd, err := unix.Dup(int(p.fd))
	if err != nil {
		clogf("Unable to dup tun fd: %v", err)
		return -1, err
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		clogf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1, err
	}
	return int32(dupTunFd), nil
}

type ipnService struct {
	fd int32
}

func newIPNService(fd int32) *ipnService {
	return &ipnService{fd: fd}
}

func (s *ipnService) ID() string {
	return fmt.Sprintf("FD:%v", s.fd)
}

func (s *ipnService) Protect(fd int32) bool {
	// Not-yet-impleneted but returns true to avoid noise.
	return true
}

func (s *ipnService) NewBuilder() libtailscale.VPNServiceBuilder {
	return newVPNBuilder()
}

func (s *ipnService) Close() {
	// Set network setting to nil
	clogf("Closing VPN service. Clearing network settings.")
	if err := setNetworkSettings(NetworkSettings{}); err != nil {
		clogf("Failed to clear network settings: %v", err)
	}
}

func (s *ipnService) DisconnectVPN() {
	// not-implemeted yet.
	// Send packet tunnel update?
}

func (s *ipnService) UpdateVpnStatus(bool) {
	// Send packet tunnel update?
}

func requestVPN(fd int32) {
	service = newIPNService(fd)
	libtailscale.RequestVPN(service)
}

func turnOffVPN() error {
	if service == nil {
		clogf("Turn off VPN skipped: not started before.")
		return fmt.Errorf("vpn service has not started")
	}
	if cachedNetworkSettings == nil {
		clogf("Turn off VPN skipped: no cached network settings.")
		return nil
	}
	clogf("Turn off VPN: skip clearing network settings.")
	return nil
}

func clearNetworkSettings() {
	clogf("Clearing network settings.")
	if cachedNetworkSettings == nil {
		clogf("No cached network settings to clear.")
		return
	}
	if err := setNetworkSettings(NetworkSettings{}); err != nil {
		clogf("Failed to clear network settings: %v", err)
	}
	cachedNetworkSettings = nil
}
