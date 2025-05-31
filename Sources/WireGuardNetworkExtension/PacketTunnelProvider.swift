// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import BackgroundTasks
import Foundation
import NetworkExtension
import os

class PacketTunnelProvider: NEPacketTunnelProvider {
    override init() {
        wg_log(.debug, message: "Process ID&&&&&&&&&&&&&&&: \(ProcessInfo.processInfo.processIdentifier)")
        wg_log(.info, message: "PacketTunnelProvider init called")
        wg_log(.info, message: "Process ID: \(ProcessInfo.processInfo.processIdentifier)")
        wg_log(.info, message: "Process name: \(ProcessInfo.processInfo.processName)")
        super.init()
    }

    private lazy var adapter: WireGuardAdapter = {
        // Add initialization logging
        wg_log(.info, message: "====1======= PacketTunnelProvider initialization =======1====")
        wg_log(.info, message: "Bundle identifier: \(Bundle.main.bundleIdentifier ?? "unknown")")
        wg_log(.info, message: "Process path: \(Bundle.main.executablePath ?? "unknown")")
        wg_log(.info, message: "Bundle path: \(Bundle.main.bundlePath)")

        if let info = Bundle.main.infoDictionary {
            wg_log(.info, message: "Info.plist contents:")
            for (key, value) in info {
                wg_log(.info, message: "  \(key): \(value)")
            }
        }

        let fd = self.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32
        let adapter = WireGuardAdapter(with: self) { logLevel, message in
            wg_log(logLevel.osLogLevel, message: message)
        }
        return adapter
    }()

    deinit {
        wg_log(.info, staticMessage: "Tunnel is deallocated...")
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        Logger.configureGlobal(tagged: "NET", withFilePath: FileManager.logFileURL?.path)
        wg_log(.info, message: "Network Extension Process ID: \(ProcessInfo.processInfo.processIdentifier)")
        wg_log(.info, message: "Network Extension Bundle ID: \(Bundle.main.bundleIdentifier ?? "unknown")")

        let activationAttemptId = options?["activationAttemptId"] as? String
        let errorNotifier = ErrorNotifier(activationAttemptId: activationAttemptId)

        wg_log(.info, staticMessage: "Starting tunnel...")

        wg_log(.info, message: "Starting tunnel from the " + (activationAttemptId == nil ? "OS directly, rather than the app" : "app"))

        checkOnDemandSettingsOnStart(activationAttemptId) // __CYLONIX_MOD__
        guard let tunnelProviderProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let tunnelConfiguration = tunnelProviderProtocol.asTunnelConfiguration()
        else {
            wg_log(.error, staticMessage: "Starting tunnel with invalid proto or config")
            errorNotifier.notify(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            completionHandler(PacketTunnelProviderError.savedProtocolConfigurationIsInvalid)
            return
        }

        // Start the tunnel
        wg_log(.info, staticMessage: "Starting tunnel adapter")
        adapter.start(tunnelConfiguration: tunnelConfiguration) { adapterError in
            guard let adapterError = adapterError else {
                let interfaceName = self.adapter.interfaceName ?? "unknown"

                wg_log(.info, message: "Tunnel interface is \(interfaceName)")

                completionHandler(nil)
                return
            }

            switch adapterError {
            case .cannotLocateTunnelFileDescriptor:
                wg_log(.error, staticMessage: "Starting tunnel failed: could not determine file descriptor")
                errorNotifier.notify(PacketTunnelProviderError.couldNotDetermineFileDescriptor)
                completionHandler(PacketTunnelProviderError.couldNotDetermineFileDescriptor)

            case let .dnsResolution(dnsErrors):
                let hostnamesWithDnsResolutionFailure = dnsErrors.map { $0.address }
                    .joined(separator: ", ")
                wg_log(.error, message: "DNS resolution failed for the following hostnames: \(hostnamesWithDnsResolutionFailure)")
                errorNotifier.notify(PacketTunnelProviderError.dnsResolutionFailure)
                completionHandler(PacketTunnelProviderError.dnsResolutionFailure)

            case let .setNetworkSettings(error):
                wg_log(.error, message: "Starting tunnel failed with setTunnelNetworkSettings returning \(error.localizedDescription)")
                errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
                completionHandler(PacketTunnelProviderError.couldNotSetNetworkSettings)

            case let .startWireGuardBackend(errorCode):
                wg_log(.error, message: "Starting tunnel failed with wgTurnOn returning \(errorCode)")
                errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
                completionHandler(PacketTunnelProviderError.couldNotStartBackend)

            case .invalidState:
                wg_log(.error, staticMessage: "Static tunnel fatal error!")
                // Must never happen
                fatalError()
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        wg_log(.info, message: "Stopping tunnel due to \(reason)")

        checkOnDemandSettingsOnStop(reason: reason, completionHandler: completionHandler) // __CYLONIX_MOD__
    }

    private func completeStop(_ completionHandler: @escaping () -> Void) {
        adapter.stop { error in
            ErrorNotifier.removeLastErrorFile()

            if let error = error {
                wg_log(.error, message: "Failed to stop WireGuard adapter: \(error.localizedDescription)")
            }
            completionHandler()

            #if os(macOS)
                // HACK: This is a filthy hack to work around Apple bug 32073323 (dup'd by us as 47526107).
                // Remove it when they finally fix this upstream and the fix has been rolled out to
                // sufficient quantities of users.
                exit(0)
            #endif
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        if let json = try? JSONSerialization.jsonObject(with: messageData, options: []) as? [String: Any] {
            if let method = json["method"] as? String {
                // wg_log(.debug, message: "packet tunnel message received: \(json)")
                switch method {
                case "get_config":
                    guard let completionHandler = completionHandler else {
                        wg_log(.error, staticMessage: "PT: get config with no completion handler")
                        return
                    }
                    adapter.getRuntimeConfiguration { settings in
                        var data: Data?
                        if let settings = settings {
                            data = settings.data(using: .utf8)!
                            completionHandler(data)
                            return
                        }
                    }
                default:
                    handleAppCommands(method, json["arguments"] as? String ?? "", completionHandler)
                    return
                }
            }
        }
        let messageString = String(data: messageData, encoding: .utf8)
        let msg = "Failed to handle the message: \(messageString as Optional)"
        wg_log(.error, message: msg)
        if let completionHandler = completionHandler {
            let data = msg.data(using: .utf8)
            completionHandler(data)
        }
    }
}

extension WireGuardLogLevel {
    var osLogLevel: OSLogType {
        switch self {
        case .verbose:
            return .debug
        case .error:
            return .error
        }
    }
}

extension PacketTunnelProvider {
    private func checkOnDemandSettingsOnStart(_ activationAttemptId: String?) {
        // Check if on-demand was enabled from system settings
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                wg_log(.error, message: "Failed to load tunnel managers: \(error.localizedDescription)")
            } else if let ourManager = managers?.first(where: { manager in
                guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
                return proto.providerBundleIdentifier == Bundle.main.bundleIdentifier && manager.isEnabled
            }) {
                if activationAttemptId != nil, !ourManager.isOnDemandEnabled {
                    wg_log(.info, message: "On-demand was disabled from system settings, enabling it")
                    ourManager.isOnDemandEnabled = true
                    ourManager.saveToPreferences { error in
                        if let error = error {
                            wg_log(.error, message: "Failed to enable on-demand rules: \(error.localizedDescription)")
                        } else {
                            wg_log(.info, message: "Successfully enabled on-demand rules")
                        }
                    }
                }
            }
        }
    }

    private func checkOnDemandSettingsOnStop(reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        if reason != .userInitiated {
            completeStop(completionHandler)
            return
        }
        // Check if tunnel is being stopped from system settings
        guard let tunnelProviderProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
            wg_log(.error, staticMessage: "Stopping tunnel with invalid proto")
            completeStop(completionHandler)
            return
        }
        // Get our specific tunnel manager using our bundle ID
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            // Check if we have an error
            if let error = error {
                wg_log(.error, message: "Failed to load tunnel managers: \(error.localizedDescription)")
                self.completeStop(completionHandler)
                return
            }

            // Find our active tunnel configuration
            guard let ourManager = managers?.first(where: { manager in
                guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
                return proto.providerBundleIdentifier == Bundle.main.bundleIdentifier && manager.isEnabled
            }) else {
                wg_log(.error, message: "Could not find our tunnel configuration")
                self.completeStop(completionHandler)
                return
            }

            if !ourManager.isOnDemandEnabled {
                wg_log(.info, message: "On-demand was already disabled from system settings")
                self.completeStop(completionHandler)
                return
            }

            // Update the configuration
            ourManager.protocolConfiguration = tunnelProviderProtocol
            ourManager.isOnDemandEnabled = false
            ourManager.saveToPreferences { error in
                if let error = error {
                    wg_log(.error, message: "Failed to disable on-demand rules: \(error.localizedDescription)")
                } else {
                    wg_log(.info, message: "Successfully disabled on-demand rules")
                }
                self.completeStop(completionHandler)
            }
        }
    }
}

extension PacketTunnelProvider {
    private func handleAppCommands(_ method: String, _ args: String, _ completionHandler: ((Data?) -> Void)?) {
        let appCmdQueue = DispatchQueue(label: "io.cylonix.sase.wireguard.appCmdQueue", qos: .userInitiated)
        appCmdQueue.async {
            var ret = "Failed to send command '\(method)' to service"
            if let result = wgSendCommand(method, args) {
                ret = String(cString: result)
                free(result)
            }
            if let completionHandler = completionHandler {
                if let data = ret.data(using: .utf8) {
                    completionHandler(data)
                } else {
                    wg_log(.error, message: "Failed to handle app command: \(method) with args: \(args): failed to convert response to Data")
                    completionHandler(nil)
                }
            }
        }
    }
}
