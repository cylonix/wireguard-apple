// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension
import UserNotifications
#if os(macOS)
import IOKit
#endif
#if SWIFT_PACKAGE
import WireGuardKitGo
import WireGuardKitC
import CoreText
#endif

public enum WireGuardAdapterError: Error {
    /// Failure to locate tunnel file descriptor.
    case cannotLocateTunnelFileDescriptor

    /// Failure to perform an operation in such state.
    case invalidState

    /// Failure to resolve endpoints.
    case dnsResolution([DNSResolutionError])

    /// Failure to set network settings.
    case setNetworkSettings(Error)

    /// Failure to start WireGuard backend.
    case startWireGuardBackend(Int32)
}

/// Enum representing internal state of the `WireGuardAdapter`
private enum State {
    /// The tunnel is stopped
    case stopped

    /// The tunnel is up and running
    case started(_ handle: Int32, _ settingsGenerator: PacketTunnelSettingsGenerator)

    /// The tunnel is temporarily shutdown due to device going offline
    case temporaryShutdown(_ settingsGenerator: PacketTunnelSettingsGenerator)
}

struct WireGuardNetworkSettingsConfig: Codable {
    var mtu: Int?
    var addresses: [String]?
    var routes: [String]?
    var excludedRoutes: [String]?
    var dnsServers: [String]?
    var searchDomains: [String]?
}

public class WireGuardAdapter {
    public typealias LogHandler = (WireGuardLogLevel, String) -> Void

    /// Network routes monitor.
    private var networkMonitor: NWPathMonitor?

    /// Packet tunnel provider.
    private weak var packetTunnelProvider: NEPacketTunnelProvider?

    /// Log handler closure.
    private let logHandler: LogHandler

    /// Private queue used to synchronize access to `WireGuardAdapter` members.
    private let workQueue = DispatchQueue(label: "WireGuardAdapterWorkQueue")

    /// Adapter state.
    private var state: State = .stopped

    /// Last network settings generator.
    private var lastNetworkSettingsGenerator: PacketTunnelSettingsGenerator?

    /// Tunnel device file descriptor.
    private var tunnelFileDescriptor: Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                return fd
            }
        }
        return nil
    }

    /// Returns a WireGuard version.
    class var backendVersion: String {
        guard let ver = wgVersion() else { return "unknown" }
        let str = String(cString: ver)
        free(UnsafeMutableRawPointer(mutating: ver))
        return str
    }

    /// Returns the tunnel device interface name, or nil on error.
    /// - Returns: String.
    public var interfaceName: String? {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else { return nil }

        var buffer = [UInt8](repeating: 0, count: Int(IFNAMSIZ))

        return buffer.withUnsafeMutableBufferPointer { mutableBufferPointer in
            guard let baseAddress = mutableBufferPointer.baseAddress else { return nil }

            var ifnameSize = socklen_t(IFNAMSIZ)
            let result = getsockopt(
                tunnelFileDescriptor,
                2 /* SYSPROTO_CONTROL */,
                2 /* UTUN_OPT_IFNAME */,
                baseAddress,
                &ifnameSize)

            if result == 0 {
                return String(cString: baseAddress)
            } else {
                return nil
            }
        }
    }

    // MARK: - Initialization

    /// Designated initializer.
    /// - Parameter packetTunnelProvider: an instance of `NEPacketTunnelProvider`. Internally stored
    ///   as a weak reference.
    /// - Parameter logHandler: a log handler closure.
    public init(with packetTunnelProvider: NEPacketTunnelProvider, logHandler: @escaping LogHandler) {
        wg_log(.info, message: "WireGuardAdapter initialized with version \(WireGuardAdapter.backendVersion)")
        self.packetTunnelProvider = packetTunnelProvider
        self.logHandler = logHandler

        self.setupLogHandler()
        self.cylonixInit() // __CYLONIX_MOD__
    }

    deinit {
        // Force remove logger to make sure that no further calls to the instance of this class
        // can happen after deallocation.
        wgSetLogger(nil, nil)

        // Cancel network monitor
        networkMonitor?.cancel()

        // Shutdown the tunnel
        if case .started(let handle, _) = self.state {
            wgTurnOff(handle)
        }
    }

    // MARK: - Public methods

    /// Returns a runtime configuration from WireGuard.
    /// - Parameter completionHandler: completion handler.
    public func getRuntimeConfiguration(completionHandler: @escaping (String?) -> Void) {
        workQueue.async {
            guard case .started(let handle, _) = self.state else {
                completionHandler(nil)
                return
            }

            if let settings = wgGetConfig(handle) {
                completionHandler(String(cString: settings))
                free(settings)
            } else {
                completionHandler(nil)
            }
        }
    }

    /// Start the tunnel tunnel.
    /// - Parameters:
    ///   - tunnelConfiguration: tunnel configuration.
    ///   - completionHandler: completion handler.
    public func start(tunnelConfiguration: TunnelConfiguration, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            guard case .stopped = self.state else {
                wg_log(.error, message: "Start: invalid state \(self.state)")
                completionHandler(.invalidState)
                return
            }

            let networkMonitor = NWPathMonitor()
            networkMonitor.pathUpdateHandler = { [weak self] path in
                self?.didReceivePathUpdate(path: path)
            }
            networkMonitor.start(queue: self.workQueue)

            do {
                let settingsGenerator = try self.makeSettingsGenerator(with: tunnelConfiguration)
                if let generator = self.lastNetworkSettingsGenerator {
                    wg_log(.info, staticMessage: "Start: re-apply cached network setting.")
                    try self.setNetworkSettings(generator.generateNetworkSettings())
                } else {
                    wg_log(.info, staticMessage: "Start: no cached network setting. Use default generator.")
                    try self.setNetworkSettings(PacketTunnelSettingsGenerator().generateNetworkSettings())
                }

                let (wgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                self.logEndpointResolutionResults(resolutionResults)

                self.state = .started(
                    try self.startWireGuardBackend(wgConfig: wgConfig),
                    settingsGenerator
                )
                self.networkMonitor = networkMonitor
                completionHandler(nil)
            } catch let error as WireGuardAdapterError {
                networkMonitor.cancel()
                completionHandler(error)
            } catch {
                fatalError()
            }
        }
    }

    /// Stop the tunnel.
    /// - Parameter completionHandler: completion handler.
    public func stop(completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            switch self.state {
            case .started(let handle, _):
                wgTurnOff(handle)

            case .temporaryShutdown:
                break

            case .stopped:
                completionHandler(.invalidState)
                return
            }

            self.networkMonitor?.cancel()
            self.networkMonitor = nil

            self.state = .stopped

            completionHandler(nil)
        }
    }

    /// Update runtime configuration.
    /// - Parameters:
    ///   - tunnelConfiguration: tunnel configuration.
    ///   - completionHandler: completion handler.
    public func update(tunnelConfiguration: TunnelConfiguration, completionHandler: @escaping (WireGuardAdapterError?) -> Void) {
        workQueue.async {
            if case .stopped = self.state {
                completionHandler(.invalidState)
                return
            }

            // Tell the system that the tunnel is going to reconnect using new WireGuard
            // configuration.
            // This will broadcast the `NEVPNStatusDidChange` notification to the GUI process.
            self.packetTunnelProvider?.reasserting = true
            wg_log(.info, staticMessage: "update wg tunnel, setting tunnel reasserting status")
            defer {
                self.packetTunnelProvider?.reasserting = false
            }

            do {
                let settingsGenerator = try self.makeSettingsGenerator(with: tunnelConfiguration)
                 if let generator = self.lastNetworkSettingsGenerator {
                    wg_log(.info, staticMessage: "Update: re-apply cached network setting.")
                    try self.setNetworkSettings(generator.generateNetworkSettings())
                } else {
                    wg_log(.info, staticMessage: "Update: no cached network setting. Use default generator.")
                    try self.setNetworkSettings(PacketTunnelSettingsGenerator().generateNetworkSettings())
                }

                switch self.state {
                case .started(let handle, _):
                    let (wgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                    self.logEndpointResolutionResults(resolutionResults)

                    wgSetConfig(handle, wgConfig)
                    #if os(iOS)
                    wgDisableSomeRoamingForBrokenMobileSemantics(handle)
                    #endif

                    self.state = .started(handle, settingsGenerator)

                case .temporaryShutdown:
                    self.state = .temporaryShutdown(settingsGenerator)

                case .stopped:
                    fatalError()
                }

                completionHandler(nil)
            } catch let error as WireGuardAdapterError {
                completionHandler(error)
            } catch {
                fatalError()
            }
        }
    }

    // MARK: - Private methods

    /// Setup WireGuard log handler.
    private func setupLogHandler() {
        wg_log(.info, staticMessage: "setting up wg log handler")
        let context = Unmanaged.passUnretained(self).toOpaque()
        wgSetLogger(context) { context, logLevel, message in
            guard let context = context, let message = message else { return }
            autoreleasepool {
                let unretainedSelf = Unmanaged<WireGuardAdapter>.fromOpaque(context)
                    .takeUnretainedValue()

                let swiftString = String(cString: message).trimmingCharacters(in: .newlines)
                let tunnelLogLevel = WireGuardLogLevel(rawValue: logLevel) ?? .verbose

                unretainedSelf.logHandler(tunnelLogLevel, swiftString)
            }
        }
    }

    /// Set network tunnel configuration.
    /// This method ensures that the call to `setTunnelNetworkSettings` does not time out, as in
    /// certain scenarios the completion handler given to it may not be invoked by the system.
    ///
    /// - Parameters:
    ///   - networkSettings: an instance of type `NEPacketTunnelNetworkSettings`.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: `PacketTunnelSettingsGenerator`.
    private func setNetworkSettings(_ networkSettings: NEPacketTunnelNetworkSettings) throws {
        logHandler(.verbose, """
            Setting tunnel network settings:
            - DNS Servers: \(networkSettings.dnsSettings?.servers ?? [])
            - Search Domains: \(networkSettings.dnsSettings?.searchDomains ?? [])
            - MTU: \(networkSettings.mtu ?? 0)
            - IPv4: \(networkSettings.ipv4Settings?.debugDescription ?? "nil")
            - IPv6: \(networkSettings.ipv6Settings?.debugDescription ?? "nil")
            """)
        var systemError: Error?
        let condition = NSCondition()

        // Activate the condition
        condition.lock()
        defer { condition.unlock() }

        packetTunnelProvider?.setTunnelNetworkSettings(networkSettings) { error in
            self.logHandler(.verbose, "setTunnelNetworkSettings callback, error: \(String(describing: error))")
            systemError = error
            condition.signal()
        }

        // Packet tunnel's `setTunnelNetworkSettings` times out in certain
        // scenarios & never calls the given callback.
        let setTunnelNetworkSettingsTimeout: TimeInterval = 5 // seconds

        if condition.wait(until: Date().addingTimeInterval(setTunnelNetworkSettingsTimeout)) {
            if let systemError = systemError {
                throw WireGuardAdapterError.setNetworkSettings(systemError)
            }
        } else {
            self.logHandler(.error, "setTunnelNetworkSettings timed out after 5 seconds; proceeding anyway")
        }
    }

    /// Resolve peers of the given tunnel configuration.
    /// - Parameter tunnelConfiguration: tunnel configuration.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: The list of resolved endpoints.
    private func resolvePeers(for tunnelConfiguration: TunnelConfiguration) throws -> [Endpoint?] {
        let endpoints = tunnelConfiguration.peers.map { $0.endpoint }
        let resolutionResults = DNSResolver.resolveSync(endpoints: endpoints)
        let resolutionErrors = resolutionResults.compactMap { result -> DNSResolutionError? in
            if case .failure(let error) = result {
                return error
            } else {
                return nil
            }
        }
        assert(endpoints.count == resolutionResults.count)
        guard resolutionErrors.isEmpty else {
            throw WireGuardAdapterError.dnsResolution(resolutionErrors)
        }

        let resolvedEndpoints = resolutionResults.map { result -> Endpoint? in
            // swiftlint:disable:next force_try
            return try! result?.get()
        }

        return resolvedEndpoints
    }

    /// Start WireGuard backend.
    /// - Parameter wgConfig: WireGuard configuration
    /// - Throws: an error of type `WireGuardAdapterError`
    /// - Returns: tunnel handle
    private func startWireGuardBackend(wgConfig: String) throws -> Int32 {
        guard let tunnelFileDescriptor = self.tunnelFileDescriptor else {
            throw WireGuardAdapterError.cannotLocateTunnelFileDescriptor
        }

        let handle = wgTurnOn(wgConfig, tunnelFileDescriptor)
        if handle < 0 {
            throw WireGuardAdapterError.startWireGuardBackend(handle)
        }
        #if os(iOS)
        wgDisableSomeRoamingForBrokenMobileSemantics(handle)
        #endif
        return handle
    }

    /// Resolves the hostnames in the given tunnel configuration and return settings generator.
    /// - Parameter tunnelConfiguration: an instance of type `TunnelConfiguration`.
    /// - Throws: an error of type `WireGuardAdapterError`.
    /// - Returns: an instance of type `PacketTunnelSettingsGenerator`.
    private func makeSettingsGenerator(with tunnelConfiguration: TunnelConfiguration) throws -> PacketTunnelSettingsGenerator {
        return PacketTunnelSettingsGenerator(
            tunnelConfiguration: tunnelConfiguration,
            resolvedEndpoints: try self.resolvePeers(for: tunnelConfiguration)
        )
    }

    /// Log DNS resolution results.
    /// - Parameter resolutionErrors: an array of type `[DNSResolutionError]`.
    private func logEndpointResolutionResults(_ resolutionResults: [EndpointResolutionResult?]) {
        for case .some(let result) in resolutionResults {
            switch result {
            case .success((let sourceEndpoint, let resolvedEndpoint)):
                if sourceEndpoint.host == resolvedEndpoint.host {
                    self.logHandler(.verbose, "DNS64: mapped \(sourceEndpoint.host) to itself.")
                } else {
                    self.logHandler(.verbose, "DNS64: mapped \(sourceEndpoint.host) to \(resolvedEndpoint.host)")
                }
            case .failure(let resolutionError):
                self.logHandler(.error, "Failed to resolve endpoint \(resolutionError.address): \(resolutionError.errorDescription ?? "(nil)")")
            }
        }
    }

    /// Helper method used by network path monitor.
    /// - Parameter path: new network path
    private func didReceivePathUpdate(path: Network.NWPath) {
        self.logHandler(.verbose, "Network change detected with \(path.status) route and interface order \(path.availableInterfaces): \(path.unsatisfiedReason) \(path.debugDescription)")

        #if os(macOS)
        if case .started(let handle, _) = self.state {
            wgBumpSockets(handle)
        }
        #elseif os(iOS)
        switch self.state {
        case .started(let handle, let settingsGenerator):
            if path.status.isSatisfiable {
                let (wgConfig, resolutionResults) = settingsGenerator.endpointUapiConfiguration()
                self.logEndpointResolutionResults(resolutionResults)

                self.logHandler(.verbose, "Connectivity is good, set config and bump the sockets")
                wgSetConfig(handle, wgConfig)
                wgDisableSomeRoamingForBrokenMobileSemantics(handle)
                wgBumpSockets(handle)
            } else {
                self.logHandler(.verbose, "Connectivity offline, pausing backend.")

                self.state = .temporaryShutdown(settingsGenerator)
                wgTurnOff(handle)
            }

        case .temporaryShutdown(let settingsGenerator):
            guard path.status.isSatisfiable else { return }

            self.logHandler(.verbose, "Connectivity online, resuming backend.")
            do {
                if let generator = self.lastNetworkSettingsGenerator {
                    wg_log(.info, staticMessage: "Connectivity online: re-apply cached network setting.")
                    try self.setNetworkSettings(generator.generateNetworkSettings())
                } else {
                    wg_log(.info, staticMessage: "Connectivity online: no cached network setting. Use default generator.")
                    try self.setNetworkSettings(PacketTunnelSettingsGenerator().generateNetworkSettings())
                }

                let (wgConfig, resolutionResults) = settingsGenerator.uapiConfiguration()
                self.logEndpointResolutionResults(resolutionResults)

                self.state = .started(
                    try self.startWireGuardBackend(wgConfig: wgConfig),
                    settingsGenerator
                )
            } catch {
                self.logHandler(.error, "Restart failed: \(error.localizedDescription). Hard resetting")
                self.packetTunnelProvider?.cancelTunnelWithError(error)
            }

        case .stopped:
            // no-op
            break
        }
        #else
        #error("Unsupported")
        #endif
    }
}

/// A enum describing WireGuard log levels defined in `api-apple.go`.
public enum WireGuardLogLevel: Int32 {
    case verbose = 0
    case error = 1
}

private extension Network.NWPath.Status {
    /// Returns `true` if the path is potentially satisfiable.
    var isSatisfiable: Bool {
        switch self {
        case .requiresConnection, .satisfied:
            return true
        case .unsatisfied:
            return false
        @unknown default:
            return true
        }
    }
}

/// Mark -- Cylonix extension
extension WireGuardAdapter {
    private func cylonixInit() {
        setupCylonixHandler()
        checkUserNotificationPermission()
        setupDarwinNotificationMessageObserver()
    }

    /// Set up cylonix handlers
    private func setupCylonixHandler() {
        wg_log(.info, message: "Setting up cylonix handlers")
        let context = Unmanaged.passUnretained(self).toOpaque()
        let systemInfo: [String: String] = [
            "shared_folder_url": FileManager.sharedFolderURL?.path ?? "",
            "os_version": ProcessInfo.processInfo.operatingSystemVersionString,
            "device_model": {
                #if os(iOS)
                    var systemInfo = utsname()
                    uname(&systemInfo)
                    let modelCode = withUnsafePointer(to: &systemInfo.machine) {
                        $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                            ptr in String(validatingUTF8: ptr)
                        }
                    } ?? "Unknown"
                    // Map common device identifiers to marketing names
                    let modelMap = [
                        "iPhone10,3": "iPhone X", // iPhone X (GSM)
                        "iPhone10,6": "iPhone X", // iPhone X (Global)
                        "iPhone11,2": "iPhone XS", // iPhone XS
                        "iPhone11,4": "iPhone XS Max", // iPhone XS Max (China)
                        "iPhone11,6": "iPhone XS Max", // iPhone XS Max
                        "iPhone11,8": "iPhone XR", // iPhone XR

                        "iPhone12,1": "iPhone 11",
                        "iPhone12,3": "iPhone 11 Pro",
                        "iPhone12,5": "iPhone 11 Pro Max",

                        "iPhone13,1": "iPhone 12 mini",
                        "iPhone13,2": "iPhone 12",
                        "iPhone13,3": "iPhone 12 Pro",
                        "iPhone13,4": "iPhone 12 Pro Max",

                        "iPhone14,2": "iPhone 13 Pro",
                        "iPhone14,3": "iPhone 13 Pro Max",
                        "iPhone14,4": "iPhone 13 mini",
                        "iPhone14,5": "iPhone 13",

                        "iPhone14,7": "iPhone 14",
                        "iPhone14,8": "iPhone 14 Plus",
                        "iPhone15,2": "iPhone 14 Pro",
                        "iPhone15,3": "iPhone 14 Pro Max",

                        "iPhone16,1": "iPhone 15 Pro",
                        "iPhone16,2": "iPhone 15 Pro Max",
                        "iPhone16,3": "iPhone 15",
                        "iPhone16,4": "iPhone 15 Plus",

                        "iPad13,4": "iPad Pro 11-inch (3rd generation)",
                        "iPad13,8": "iPad Pro 12.9-inch (5th generation)",
                        "iPad13,16": "iPad Pro 11-inch (4th generation)",
                        "iPad13,17": "iPad Pro 12.9-inch (6th generation)",
                        // Add more mappings as needed
                    ]
                    return modelMap[modelCode] ?? modelCode // Return marketing name if available, otherwise return identifier

                #else
                    // Get Mac model identifier
                    let service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                              IOServiceMatching("IOPlatformExpertDevice"))
                    defer { IOObjectRelease(service) }

                    if let modelData = IORegistryEntryCreateCFProperty(service,
                                                                       "model" as CFString,
                                                                       kCFAllocatorDefault, 0).takeRetainedValue() as? Data,
                        let modelString = String(data: modelData, encoding: .utf8)?.trimmingCharacters(in: .controlCharacters)
                    {
                        // Map common Mac identifiers to marketing names
                        let macModelMap = [
                            // Mac Mini
                            "Macmini9,1": "Mac mini (M1, 2020)",
                            "Macmini8,1": "Mac mini (2018)",
                            // iMac
                            "iMac21,1": "iMac 24-inch (M1, 2021)",
                            "iMac20,1": "iMac 27-inch (2020)",
                            // MacBook Pro
                            "MacBookPro18,1": "MacBook Pro 16-inch (M1 Pro/Max, 2021)",
                            "MacBookPro18,2": "MacBook Pro 16-inch (M1 Pro/Max, 2021)",
                            "MacBookPro17,1": "MacBook Pro 13-inch (M1, 2020)",
                            // MacBook Air
                            "MacBookAir10,1": "MacBook Air (M1, 2020)",
                            "MacBookAir9,1": "MacBook Air (Retina, 2020)",
                            // Mac Pro
                            "MacPro7,1": "Mac Pro (2019)",
                            // Mac Studio
                            "Mac13,1": "Mac Studio (M1 Max, 2022)",
                            "Mac13,2": "Mac Studio (M1 Ultra, 2022)",
                        ]
                        return macModelMap[modelString] ?? modelString
                    }
                    return "Mac"
                #endif
            }(),
        ]

        // Convert to JSON string
        let jsonData = try? JSONSerialization.data(withJSONObject: systemInfo)
        let systemInfoJson = String(data: jsonData ?? Data(), encoding: .utf8) ?? "{}"

        wgSetAdapter(systemInfoJson, context) { context, method, args, buf, len in
            // wg_log(.debug, message: "Cylonix adapter call received")
            guard let context = context, let buf = buf, len > 128 else {
                wg_log(.error, message: "bad buf or len")
                return
            }
            autoreleasepool {
                let unretainedSelf = Unmanaged<WireGuardAdapter>.fromOpaque(context)
                    .takeUnretainedValue()
                guard let method = method, let args = args else {
                    strlcpy(buf, "ERROR: invalid input", Int(len))
                    return
                }
                let cmd = String(cString: method)
                let arguments = String(cString: args)
                var ret = "ERROR: unknown"
                //wg_log(.debug, message: "Cylonix adapter call received \(cmd)")
                switch cmd {
                case "setKeychainItem":
                    // Value is base64 encoded so there should be no space in the value
                    let parts = arguments.split(separator: " ", maxSplits: 1)
                    if parts.count == 2 {
                        let k = String(parts[0])
                        let v = String(parts[1])
                        ret = Keychain.setItem(key: k, value: v)
                    } else if parts.count == 1 {
                        let k = String(parts[0])
                        ret = Keychain.setItem(key: k, value: "")
                    } else {
                        ret = "ERROR: invalid key/value arguments"
                    }
                case "getKeychainItem":
                    ret = Keychain.getItem(key: arguments)
                case "setNetworkSettings":
                    ret = unretainedSelf.setNetworkSettingsWithJsonString(arguments)
                case "ipnNotify":
                    ret = unretainedSelf.handleIpnNotify(arguments)
                case "chatsReceived":
                    ret = unretainedSelf.handleChatsReceived(arguments)
                case "chatStatus":
                    ret = unretainedSelf.handleChatStatus(arguments)
                case "filesWaiting":
                    ret = unretainedSelf.handleFilesWaiting(arguments)
                default:
                    ret = "ERROR: method \(cmd) not supported"
                }
                strlcpy(buf, ret, Int(len))
            }
        }
    }

    /// Set network tunnel configuration with config json string
    private func setNetworkSettingsWithJsonString(_ jsonString: String) -> String {
        wg_log(.info, message: "set network settings \(jsonString)")
        do {
            let json = jsonString.data(using: .utf8)!
            let decoder = JSONDecoder()
            let config = try decoder.decode(WireGuardNetworkSettingsConfig.self, from: json)
            let generator = PacketTunnelSettingsGenerator(
                addresses: config.addresses,
                routes: config.routes,
                excludedRoutes: config.excludedRoutes,
                dns: config.dnsServers,
                dnsSearch: config.searchDomains
            )
            logHandler(.verbose, "setNetworkSettingsWithJsonString: set last generator to \(generator) with config \(config) jsonString \(jsonString)")
            lastNetworkSettingsGenerator = generator
            try setNetworkSettings(generator.generateNetworkSettings())
            return ""
        } catch {
            wg_log(.error, message: "network settings error: \(error)")
            return "ERROR: network settings error: \(error)"
        }
    }

    private func sharedDefaults() -> UserDefaults? {
        guard let appGroupId = FileManager.appGroupId else {
            wg_log(.error, message: "Cannot obtain app group ID")
            return nil
        }
        return UserDefaults(suiteName: appGroupId)
    }

    private func handleIpnNotify(_ notification: String) -> String {
        let notificationCenter = CFNotificationCenterGetDarwinNotifyCenter()
        let notificationName = PacketTunnelNotification.ipnNotify as CFString
        guard let containerURL = containerURL() else {
            wg_log(.error, message: "Failed to get group container URL")
            return "ERROR: Failed to get group container URL"
        }
        let fileManager = FileManager.default

        do {
            try fileManager.createDirectory(at: containerURL, withIntermediateDirectories: true)
        } catch {
            wg_log(.error, message: "Failed to create directory '\(containerURL)': \(error.localizedDescription)")
            return "ERROR: Failed to create directory '\(containerURL)': \(error.localizedDescription)"
        }

        // Use file coordination for atomic access
        let coordinator = NSFileCoordinator()
        var coorError: NSError?

        coordinator.coordinate(writingItemAt: containerURL, options: .forMerging, error: &coorError) { url in
            // Get queue with file protection
            let queueFile = url.appendingPathComponent("notification_queue.json")
            var queue: [[String: Any]] = []

            if let data = try? Data(contentsOf: queueFile) {
                queue = (try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]) ?? []
            }

            // Add new notification
            let entry: [String: Any] = [
                "id": UUID().uuidString,
                "timestamp": floor(Date().timeIntervalSince1970 * 1_000_000), // microseconds
                "notification": notification,
            ]
            queue.append(entry)

            // Keep last 100 items
            if queue.count > 100 {
                queue.removeFirst(queue.count - 100)
            }

            // Write atomically
            if let data = try? JSONSerialization.data(withJSONObject: queue) {
                try? data.write(to: queueFile, options: .atomicWrite)
            }
            //wg_log(.info, message: "Notification queue updated with \(notification)")
        }
        if let error = coorError {
            wg_log(.error, message: "Failed to access notification queue: \(error.localizedDescription)")
            return "ERROR: Failed to access notification queue: \(error.localizedDescription)"
        }

        //wg_log(.info, message: "Notification queue updated with \(notification)")
        CFNotificationCenterPostNotification(notificationCenter, CFNotificationName(notificationName), nil, nil, true)
        return ""
    }

    private func postNotification(notification: String) {
        // Post Darwin notification that can be received by both main app and extension
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                             CFNotificationName(notification as CFString),
                                             nil,
                                             nil,
                                             true)
        wg_log(.info, message: "Posted notification: \(notification)")
    }

    private func handleFilesWaiting(_ filesWaitingDetails: String) -> String {
        guard let defaults = sharedDefaults() else {
            wg_log(.error, message: "Failed to access shared defaults")
            return "ERROR: Failed to access shared defaults"
        }
        if let currentFilesWaiting = defaults.string(forKey: PacketTunnelUserDefaultsKey.filesWaiting) {
            if currentFilesWaiting == filesWaitingDetails {
                wg_log(.info, message: "Received file details the same as pending for processing. Ignoring.")
                return ""
            }
        }
        defaults.set(filesWaitingDetails, forKey: PacketTunnelUserDefaultsKey.filesWaiting)
        defaults.synchronize()
        // Parse file details and show notification
        do {
            wg_log(.info, message: "Received file details: \(filesWaitingDetails)")
            if let json = try JSONSerialization.jsonObject(with: Data(filesWaitingDetails.utf8)) as? [String: Any],
               let files = json["Files"] as? [[String: Any]]
            {
                let fileCount = files.count
                let title = "Files Received"
                let body = fileCount == 1
                    ? "You received a new file"
                    : "You received \(fileCount) new files"

                wg_log(.info, message: "Sending User notification of Received \(fileCount) files")
                sendUserNotification(
                    title: title,
                    body: body,
                    identifier: "file-receipt-\(UUID().uuidString)"
                )
            }
        } catch {
            wg_log(.error, message: "Failed to parse files waiting details: \(error)")
            return "ERROR: Failed to parse files waiting details: \(error)"
        }
        wg_log(.info, message: "Files waiting details: \(filesWaitingDetails) get result: \(defaults.string(forKey: "FilesWaiting") ?? "nil")")
        // wg_log(.info, message: "Files waiting details: \(filesWaitingDetails)")
        postNotification(notification: PacketTunnelNotification.filesWaiting)
        return ""
    }

    private func handleChatsReceived(_ chatsReceived: String) -> String {
        guard let defaults = sharedDefaults() else {
            wg_log(.error, message: "Failed to access shared defaults")
            return "ERROR: Failed to access shared defaults"
        }
        defaults.set(chatsReceived, forKey: PacketTunnelUserDefaultsKey.chatsReceived)
        defaults.synchronize()
        postNotification(notification: PacketTunnelNotification.chatsReceived)
        return ""
    }

    private func handleChatStatus(_ status: String) -> String {
        guard let defaults = sharedDefaults() else {
            wg_log(.error, message: "Failed to access shared defaults")
            return "ERROR: Failed to access shared defaults"
        }
        defaults.set(status, forKey: PacketTunnelUserDefaultsKey.chatStatus)
        defaults.synchronize()
        postNotification(notification: PacketTunnelNotification.chatStatus)
        return ""
    }

    private func sendUserNotification(title: String, body: String, identifier: String? = nil) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default

        // Add threadIdentifier to group related notifications
        content.threadIdentifier = PacketTunnelNotification.userNotification

        // Create unique identifier if none provided
        let notificationId = identifier ?? UUID().uuidString

        // Create request with content
        let request = UNNotificationRequest(
            identifier: notificationId,
            content: content,
            trigger: nil // Deliver immediately
        )
        wg_log(.info, message: "Scheduling notification with id: \(notificationId)")

        // Schedule notification
        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                wg_log(.error, message: "Failed to schedule notification: \(error.localizedDescription)")
            } else {
                wg_log(.info, message: "Successfully scheduled notification with id: \(notificationId)")
            }
        }
    }

    fileprivate func handleDarwinNotification(_ cfName: CFNotificationName?) {
        guard
            let raw = cfName?.rawValue as String?,
            raw.hasPrefix(PacketTunnelMessage.prefix),
            !raw.hasSuffix(".response")
        else {
            wg_log(.error, message: "handleDarwinNotification: Invalid notification name \(String(describing: cfName))")
            return
        }
        let name = raw

        wg_log(.info, message: "handleDarwinNotification: Received notification \(name)")
        guard let group = containerURL() else {
            wg_log(.error, message: "handleDarwinNotification: Failed to get group container URL")
            return
        }
        let msgURL = group.appendingPathComponent(PacketTunnelMessage.messageFile(channel: name))
        let respURL = group.appendingPathComponent(PacketTunnelMessage.responseFile(channel: name))

        guard
            let data = try? Data(contentsOf: msgURL),
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let id = json["id"] as? String,
            let method = json["method"] as? String
        else {
            wg_log(.error, message: "handleDarwinNotification: Malformed message for channel \(name)")
            return
        }

        // forward via wgSendCommand
        wg_log(.info, message: "handleDarwinNotification: command '\(method)'")
        let args = json["arguments"] as? String ?? ""
        var resultString = "no-response"
        if let cstr = wgSendCommand(method, args) {
            resultString = String(cString: cstr); free(cstr)
            wg_log(.debug, message: "handleDarwinNotification: command '\(method)' response: \(String(resultString.prefix(200)))")
        } else {
            wg_log(.error, message: "handleDarwinNotification: Failed to send command '\(method)'")
        }

        // write response JSON + notify
        let respObj: [String: Any] = ["id": id, "payload": resultString]
        if let out = try? JSONSerialization.data(withJSONObject: respObj) {
            try? out.write(to: respURL, options: .atomic)
            CFNotificationCenterPostNotification(
                CFNotificationCenterGetDarwinNotifyCenter(),
                CFNotificationName((name + ".response") as CFString),
                nil, nil, true
            )
            wg_log(.info, message: "handleDarwinNotification: Response written to \(respURL.lastPathComponent)")
        }
        wg_log(.info, message: "handleDarwinNotification: Completed handling notification \(name)")
    }

    private func checkUserNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                wg_log(.error, message: "Failed to request notification authorization: \(error.localizedDescription)")
                return
            }
            if granted {
                wg_log(.info, message: "Notification authorization granted")
            } else {
                wg_log(.error, message: "Notification authorization denied")
            }
        }
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            wg_log(.info, message: "Notification settings: authorization status = \(settings.authorizationStatus.rawValue)")

            if settings.authorizationStatus == .notDetermined {
                UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
                    if let error = error {
                        wg_log(.error, message: "Failed to request notification authorization: \(error.localizedDescription)")
                        return
                    }
                    wg_log(.info, message: "Notification authorization \(granted ? "granted" : "denied")")
                }
            } else if settings.authorizationStatus == .denied {
                wg_log(.error, message: "Notifications are disabled in system settings")
            }
        }
    }

    private func setupDarwinNotificationMessageObserver() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        // explicitly listen for the "share" channel
        let shareNote = PacketTunnelMessage.share as CFString
        CFNotificationCenterAddObserver(
            center,
            Unmanaged.passUnretained(self).toOpaque(),
            packetTunnelDarwinCallback,
            shareNote,
            nil,
            .deliverImmediately
        )
        wg_log(.info, message: "Listening for Darwin notification: \(shareNote)")

        // if you have other channels, add them here:
        let tailchatNote = PacketTunnelMessage.tailchat as CFString
        CFNotificationCenterAddObserver(
            center,
            Unmanaged.passUnretained(self).toOpaque(),
            packetTunnelDarwinCallback,
            tailchatNote,
            nil,
            .deliverImmediately
        )
        wg_log(.info, message: "Listening for Darwin notification: \(tailchatNote)")
    }

    private func containerURL() -> URL? {
        return FileManager.sharedFolderURL
    }
}

private func packetTunnelDarwinCallback(
    _: CFNotificationCenter?,
    _ observerRaw: UnsafeMutableRawPointer?,
    _ cfName: CFNotificationName?,
    _: UnsafeRawPointer?,
    _: CFDictionary?
) {
    guard
        let observerRaw = observerRaw
    else {
        wg_log(.error, message: "⚠️ packetTunnelDarwinCallback: missing observer")
        return
    }
    let adapter = Unmanaged<WireGuardAdapter>
        .fromOpaque(observerRaw)
        .takeUnretainedValue()
    wg_log(.info, message: "packetTunnelDarwinCallback: Darwin notification received: \(String(describing: cfName))")

    // Create a background queue for handling notifications
    let notificationQueue = DispatchQueue(label: "io.cylonix.sase.wireguard.notificationQueue", qos: .userInitiated)

    // Handle notification asynchronously
    notificationQueue.async {
        adapter.handleDarwinNotification(cfName)
    }
}
