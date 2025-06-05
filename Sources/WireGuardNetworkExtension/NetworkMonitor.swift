import Foundation
import Network
import os.log
import NetworkExtension
#if os(macOS)
    import SystemConfiguration
#endif

class NetworkMonitor {
    private let monitor: NWPathMonitor
    private let monitorQueue = DispatchQueue(label: "io.cylonix.network-monitor")
    private var activeInterfaces: [NWInterface: LinkProperties] = [:]
 
    struct LinkProperties {
        var dnsServers: [String]
        var searchDomains: [String]
        var isMetered: Bool
        var interfaceName: String
    }

    init() {
        monitor = NWPathMonitor(requiredInterfaceType: .other)
    }

    deinit {
        // Cancel network monitor
        monitor.cancel()
    }

    private func log(_ type: OSLogType, message: String) {
        wg_log(type, message: "[NetworkMonitor]: \(message)")
    }

    func startMonitoring(dnsConfigHandler: @escaping (String, String) -> Void) {
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else {
                wg_log(.error, message: "NetworkMonitor instance was deallocated")
                return
            }

            self.log(.debug, message: "Network path updated: \(path.status)")

            // Update active interfaces
            var newInterfaces: [NWInterface: LinkProperties] = [:]
            for interface in path.availableInterfaces where !interface.type.isVPN && !self.isVPNInterface(interface) {
                if let properties = self.getLinkProperties(for: interface) {
                    newInterfaces[interface] = properties
                }
            }

            self.activeInterfaces = newInterfaces
            self.log(.debug, message: "Active interfaces: \(newInterfaces)")

            // Update DNS configuration if needed
            self.maybeUpdateDNSConfig(reason: "path-update", dnsConfigHandler: dnsConfigHandler)
        }

        monitor.start(queue: monitorQueue)
    }

    private func getLinkProperties(for interface: NWInterface) -> LinkProperties? {
        return LinkProperties(
            dnsServers: getDNSServers(for: interface),
            searchDomains: getSearchDomains(for: interface),
            isMetered: isMetered(interface: interface),
            interfaceName: interface.name
        )
    }

    private func pickDefaultNetwork() -> (NWInterface, LinkProperties)? {
        let path = monitor.currentPath

        // First, find all interfaces capable of internet connectivity
        let internetCapableInterfaces = activeInterfaces.filter { pair in
            let interface = pair.key
            log(.debug, message: "Checking interface: \(interface.name) of type \(interface.type) with \(path.usesInterfaceType(interface.type)) status \(path.status)")
            return path.usesInterfaceType(interface.type) &&
                path.status == .satisfied &&
                !interface.type.isVPN
        }

        if internetCapableInterfaces.isEmpty {
            log(.debug, message: "No internet capable interfaces found")
            return nil
        }

        log(.debug, message: "Found \(internetCapableInterfaces.count) internet capable interfaces")

        // Among internet capable interfaces, prefer non-metered with DNS servers
        let nonMetered = internetCapableInterfaces.first { pair in
            let properties = pair.value
            return !properties.isMetered && !properties.dnsServers.isEmpty
        }

        if let nonMetered = nonMetered {
            log(.debug, message: "Picked non-metered internet interface: \(nonMetered.key.name)")
            return nonMetered
        }

        // Then try any internet capable interface with DNS servers
        let withDNS = internetCapableInterfaces.first { !$0.value.dnsServers.isEmpty }
        if let withDNS = withDNS {
            log(.debug, message: "Picked internet interface with DNS: \(withDNS.key.name)")
            return withDNS
        }

        // As last resort, pick any internet capable interface
        let anyInterface = internetCapableInterfaces.first
        if let anyInterface = anyInterface {
            log(.debug, message: "Picked internet interface without DNS: \(anyInterface.key.name)")
            return anyInterface
        }

        log(.error, message: "No suitable network interfaces found")
        return nil
    }

    private func maybeUpdateDNSConfig(reason: String, dnsConfigHandler: (String, String) -> Void) {
        guard let (_, properties) = pickDefaultNetwork() else {
            log(.error, message: "\(reason): no default network available")
            return
        }

        var config = properties.dnsServers.joined(separator: " ")
        if !properties.searchDomains.isEmpty {
            config += "\n" + properties.searchDomains.joined(separator: " ")
        }

        log(.debug, message: "\(reason): updating DNS config for interface \(properties.interfaceName) with servers: \(config)")
        dnsConfigHandler(config, properties.interfaceName)
        log(.debug, message: "\(reason): updated DNS config for interface \(properties.interfaceName)")
    }

    #if os(iOS)
    private func getDNSSettings() -> NEDNSSettings? {
        return nil
    }
    
    private func getSearchDomains(for interface: NWInterface) -> [String] {
        // On iOS, use Network Extension framework
        guard let settings = getDNSSettings() else {
            return []
        }
        return settings.searchDomains ?? []
    }
    
    private func getDNSServers(for interface: NWInterface) -> [String] {
        // On iOS, use Network Extension framework
        guard let settings = getDNSSettings() else {
            return []
        }
        return settings.servers
    }
    #endif
    #if os(macOS)
    private func getDNSServers(for interface: NWInterface) -> [String] {
            let store = SCDynamicStoreCreate(nil, "NetworkMonitor" as CFString, nil, nil)
            guard let store = store else {
                log(.error, message: "Failed to create dynamic store")
                return []
            }

            let key = "State:/Network/Interface/\(interface.name)/DNS" as CFString
            guard let dict = SCDynamicStoreCopyValue(store, key) as? [String: AnyObject] else {
                log(.debug, message: "No DNS settings found for interface: \(interface.name)")
                return []
            }

            var servers: [String] = []
            if let serverAddresses = dict["ServerAddresses"] as? [String] {
                servers.append(contentsOf: serverAddresses)
            }

        log(.debug, message: "Found DNS servers for \(interface.name): \(servers)")
        return servers
    }

    private func getSearchDomains(for interface: NWInterface) -> [String] {
            let store = SCDynamicStoreCreate(nil, "NetworkMonitor" as CFString, nil, nil)
            guard let store = store else {
                log(.error, message: "Failed to create dynamic store")
                return []
            }

            let key = "State:/Network/Interface/\(interface.name)/DNS" as CFString
            guard let dict = SCDynamicStoreCopyValue(store, key) as? [String: AnyObject] else {
                log(.debug, message: "No DNS settings found for interface: \(interface.name)")
                return []
            }

            var domains: [String] = []
            if let searchDomains = dict["SearchDomains"] as? [String] {
                domains.append(contentsOf: searchDomains)
            }
            if let domain = dict["DomainName"] as? String {
                domains.append(domain)
            }

        log(.debug, message: "Found search domains for \(interface.name): \(domains)")
        return domains
    }
    #endif

    private func isMetered(interface: NWInterface) -> Bool {
        // On iOS, cellular interfaces are considered metered
        return interface.type == .cellular
    }

    private func isVPNInterface(_ interface: NWInterface) -> Bool {
        // First check interface type
        guard interface.type == .other else {
            return false
        }

        // Then check interface name for VPN indicators
        let name = interface.name.lowercased()
        return name.hasPrefix("utun") ||
            name.hasPrefix("tun") ||
            name.hasPrefix("ppp") ||
            name.hasPrefix("ipsec")
    }
}

private extension NWInterface.InterfaceType {
    var isVPN: Bool {
        switch self {
        case .other:
            // Only check interface type since we can't access name here
            // The actual name check should happen in the NetworkMonitor class
            return true
        case .cellular, .wifi, .wiredEthernet, .loopback:
            return false
        @unknown default:
            return false
        }
    }
}
