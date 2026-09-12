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

    // NWPathMonitor fires on every path attribute flicker: on a phone with
    // both radios up that was ~3,000 updates a day with the picked interface
    // changing once. Each one used to be forwarded to Go as a network change,
    // and each of those tore down and re-dialed the DERP tunnel. Forward an
    // update only when what the tunnel is bound to actually moved: the picked
    // interface, its addresses (a renumbering on the same interface kills the
    // socket too), or its DNS. Real handoffs still go through immediately.
    private var lastForwardedKey: String?
    private var skippedSinceForward = 0

    struct LinkProperties {
        var dnsServers: [String]
        var searchDomains: [String]
        var isMetered: Bool
        var interfaceName: String
    }

    init() {
        monitor = NWPathMonitor()
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

        guard path.status == .satisfied else {
            log(.debug, message: "pickDefaultNetwork: path status is \(path.status); no default network")
            return nil
        }

        // Walk the interfaces in the OS's own order of preference.
        //
        // NWPath.availableInterfaces is ordered by the system's route
        // preference, so the first usable, path-using, non-VPN interface is the
        // one the OS is actually routing through right now. We must follow that
        // ordering rather than preferring non-metered Wi-Fi out of an unordered
        // dictionary: when iOS promotes cellular to the primary path (e.g. Wi-Fi
        // goes weak and the device moves to 5G) while Wi-Fi lingers as merely
        // "available", the old logic kept nominating the stale Wi-Fi interface.
        //
        // The interface chosen here is what we feed to netmon via
        // UpdateLastKnownDefaultRouteInterface (through the DNS-config handler),
        // which in turn decides OSDefaultRoute() and whether a link change is
        // classified major. Nominating the wrong interface pins the whole
        // backend (socket binding, DERP, magicDNS) to a dead link.
        for interface in path.availableInterfaces {
            if interface.type.isVPN || isVPNInterface(interface) {
                continue
            }
            guard path.usesInterfaceType(interface.type) else {
                log(.debug, message: "Skipping interface \(interface.name): path does not use type \(interface.type)")
                continue
            }
            guard let properties = getLinkProperties(for: interface) else {
                continue
            }
            log(.debug, message: "Picked default interface in OS order: \(interface.name) type=\(interface.type) metered=\(properties.isMetered) hasDNS=\(!properties.dnsServers.isEmpty)")
            return (interface, properties)
        }

        log(.error, message: "No suitable network interfaces found in path order")
        return nil
    }

    private func maybeUpdateDNSConfig(reason: String, dnsConfigHandler: (String, String) -> Void) {
        guard let (_, properties) = pickDefaultNetwork() else {
            log(.error, message: "\(reason): no default network available")
            // The next usable path must be forwarded even if it looks like
            // the last one: the tunnel has to be re-dialed after an outage.
            lastForwardedKey = nil
            return
        }

        var config = properties.dnsServers.joined(separator: " ")
        if !properties.searchDomains.isEmpty {
            config += "\n" + properties.searchDomains.joined(separator: " ")
        }

        let addresses = interfaceAddresses(named: properties.interfaceName).joined(separator: ",")
        let key = "\(properties.interfaceName)|\(config)|\(addresses)"
        if key == lastForwardedKey {
            skippedSinceForward += 1
            if skippedSinceForward == 1 || skippedSinceForward % 100 == 0 {
                log(.debug, message: "\(reason): no change on \(properties.interfaceName) (skipped \(skippedSinceForward) updates)")
            }
            return
        }
        lastForwardedKey = key
        skippedSinceForward = 0

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

    /// Addresses currently assigned to the named interface, sorted, so that a
    /// renumbering on the same interface counts as a change.
    private func interfaceAddresses(named name: String) -> [String] {
        var result: [String] = []
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return result }
        defer { freeifaddrs(list) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            cursor = entry.pointee.ifa_next
            guard let addr = entry.pointee.ifa_addr, String(cString: entry.pointee.ifa_name) == name else { continue }
            let family = Int32(addr.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                result.append(String(cString: host))
            }
        }
        return result.sorted()
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
