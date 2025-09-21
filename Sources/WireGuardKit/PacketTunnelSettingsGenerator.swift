// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network
import NetworkExtension

#if SWIFT_PACKAGE
import WireGuardKitC
import CoreText
#endif

/// A type alias for `Result` type that holds a tuple with source and resolved endpoint.
typealias EndpointResolutionResult = Result<(Endpoint, Endpoint), DNSResolutionError>

class PacketTunnelSettingsGenerator {
    let tunnelConfiguration: TunnelConfiguration?
    let resolvedEndpoints: [Endpoint?]
    let interfaceAddresses: [IPAddressRange]
    let routes: [IPAddressRange]
    let excludedRoutes: [IPAddressRange]
    let dns: [String]
    let dnsSearch: [String]?
    let defaultMTU: UInt16?

    init(tunnelConfiguration: TunnelConfiguration, resolvedEndpoints: [Endpoint?]) {
        self.tunnelConfiguration = tunnelConfiguration
        self.resolvedEndpoints = resolvedEndpoints
        self.interfaceAddresses = []
        self.routes = []
        self.excludedRoutes = []
        self.dns = []
        self.dnsSearch = []
        self.defaultMTU = nil
    }

    init() {
        self.defaultMTU = nil
        self.tunnelConfiguration = nil
        self.resolvedEndpoints = []
        self.interfaceAddresses = []
        self.routes = []
        self.excludedRoutes = []
        self.dnsSearch = []
        self.dns = ["8.8.8.8", "8.8.4.4", "9.9.9.9", "223.5.5.5", "223.6.6.6", "114.114.114.114"]
    }

    init(addresses: [String]?, routes: [String]?, excludedRoutes: [String]?, dns: [String]?, dnsSearch: [String]?, mtu: UInt16?) {
        self.dns = dns ??  ["8.8.8.8", "8.8.4.4", "9.9.9.9", "223.5.5.5", "223.6.6.6", "114.114.114.114"]
        self.dnsSearch = dnsSearch
        var interfaceAddresses: [IPAddressRange] = []
        var tunnelRoutes: [IPAddressRange] = []
        var tunnelExcludedRoutes: [IPAddressRange] = []
        for a in addresses ?? [] {
            guard let address = IPAddressRange(from: a) else {
                wg_log(.error, message: "invalid address range: \(a)")
                continue
            }
            interfaceAddresses.append(address)
        }
        for r in routes ?? [] {
            guard let route = IPAddressRange(from: r) else {
                wg_log(.error, message: "invalid route: \(r)")
                continue
            }
            tunnelRoutes.append(route)
        }
        for r in excludedRoutes ?? [] {
            guard let route = IPAddressRange(from: r) else {
                wg_log(.error, message: "invalid excluded route: \(r)")
                continue
            }
            tunnelExcludedRoutes.append(route)
        }

        self.interfaceAddresses = interfaceAddresses
        self.routes = tunnelRoutes
        self.excludedRoutes = tunnelExcludedRoutes
        self.tunnelConfiguration = nil
        self.resolvedEndpoints = []
        self.defaultMTU = mtu
    }

    private func getInterfaceAddresses() -> [IPAddressRange] {
        if let tunnelConfig = tunnelConfiguration {
            return tunnelConfig.interface.addresses
        }
        return interfaceAddresses
    }

    private func getRoutes() -> [IPAddressRange] {
        if let tunnelConfig = tunnelConfiguration {
            var ret: [IPAddressRange] = []
            for peer in tunnelConfig.peers {
                for addressRange in peer.allowedIPs {
                    ret.append(addressRange)
                }
            }
            return ret
        }
        return routes
    }

    private func getExcludedRoutes() -> [IPAddressRange] {
        return excludedRoutes
    }

    private func getDNS() -> [String] {
        if let tunnelConfig = tunnelConfiguration {
             if !tunnelConfig.interface.dnsSearch.isEmpty ||
                !tunnelConfig.interface.dns.isEmpty {
                return tunnelConfig.interface.dns.map { $0.stringRepresentation }
            }
            return []
        }
        return dns
    }

    private func getDNSSearch() -> [String]? {
        if let tunnelConfig = tunnelConfiguration {
            return tunnelConfig.interface.dnsSearch
        }
        return dnsSearch
    }

    func endpointUapiConfiguration() -> (String, [EndpointResolutionResult?]) {
        var resolutionResults = [EndpointResolutionResult?]()
        var wgSettings = ""

        guard let tunnelConfiguration = tunnelConfiguration else {
            return ("", [])
        }

        assert(tunnelConfiguration.peers.count == resolvedEndpoints.count)
        for (peer, resolvedEndpoint) in zip(tunnelConfiguration.peers, self.resolvedEndpoints) {
            wgSettings.append("public_key=\(peer.publicKey.hexKey)\n")

            let result = resolvedEndpoint.map(Self.reresolveEndpoint)
            if case .success((_, let resolvedEndpoint)) = result {
                if case .name = resolvedEndpoint.host { assert(false, "Endpoint is not resolved") }
                wgSettings.append("endpoint=\(resolvedEndpoint.stringRepresentation)\n")
            }
            resolutionResults.append(result)
        }

        return (wgSettings, resolutionResults)
    }

    func uapiConfiguration() -> (String, [EndpointResolutionResult?]) {
        var resolutionResults = [EndpointResolutionResult?]()
        var wgSettings = ""
        guard let tunnelConfiguration = tunnelConfiguration else {
            return ("", [])
        }
        wgSettings.append("private_key=\(tunnelConfiguration.interface.privateKey.hexKey)\n")
        if let listenPort = tunnelConfiguration.interface.listenPort {
            wgSettings.append("listen_port=\(listenPort)\n")
        }
        if !tunnelConfiguration.peers.isEmpty {
            wgSettings.append("replace_peers=true\n")
        }
        assert(tunnelConfiguration.peers.count == resolvedEndpoints.count)
        for (peer, resolvedEndpoint) in zip(tunnelConfiguration.peers, self.resolvedEndpoints) {
            wgSettings.append("public_key=\(peer.publicKey.hexKey)\n")
            if let preSharedKey = peer.preSharedKey?.hexKey {
                wgSettings.append("preshared_key=\(preSharedKey)\n")
            }

            let result = resolvedEndpoint.map(Self.reresolveEndpoint)
            if case .success((_, let resolvedEndpoint)) = result {
                if case .name = resolvedEndpoint.host { assert(false, "Endpoint is not resolved") }
                wgSettings.append("endpoint=\(resolvedEndpoint.stringRepresentation)\n")
            }
            resolutionResults.append(result)

            let persistentKeepAlive = peer.persistentKeepAlive ?? 0
            wgSettings.append("persistent_keepalive_interval=\(persistentKeepAlive)\n")
            if !peer.allowedIPs.isEmpty {
                wgSettings.append("replace_allowed_ips=true\n")
                peer.allowedIPs.forEach { wgSettings.append("allowed_ip=\($0.stringRepresentation)\n") }
            }
        }
        return (wgSettings, resolutionResults)
    }

    func generateNetworkSettings() -> NEPacketTunnelNetworkSettings {
        /* iOS requires a tunnel endpoint, whereas in WireGuard it's valid for
         * a tunnel to have no endpoint, or for there to be many endpoints, in
         * which case, displaying a single one in settings doesn't really
         * make sense. So, we fill it in with this placeholder, which is not
         * a valid IP address that will actually route over the Internet.
         */
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        var dnsServerStrings = getDNS()
        if (dnsServerStrings.isEmpty) {
            dnsServerStrings = ["8.8.8.8", "8.8.4.4", "9.9.9.9", "223.5.5.5", "223.6.6.6", "114.114.114.114"]
        }
        if !dnsServerStrings.isEmpty {
            let dnsSettings = NEDNSSettings(servers: dnsServerStrings)
            dnsSettings.searchDomains = getDNSSearch()
            if !dnsServerStrings.isEmpty {
                dnsSettings.matchDomains = [""] // All DNS queries must first go through the tunnel's DNS
            }
            networkSettings.dnsSettings = dnsSettings
        }

        let mtu = tunnelConfiguration?.interface.mtu ?? self.defaultMTU ?? 1280 // __CYLONIX_MOD__

        /* 0 means automatic MTU. In theory, we should just do
         * `networkSettings.tunnelOverheadBytes = 80` but in
         * practice there are too many broken networks out there.
         * Instead set it to 1280. Boohoo. Maybe someday we'll
         * add a nob, maybe, or iOS will do probing for us.
         */
        if mtu == 0 {
            #if os(iOS)
            networkSettings.mtu = NSNumber(value: 1280)
            #elseif os(macOS)
            networkSettings.tunnelOverheadBytes = 80
            #else
            #error("Unimplemented")
            #endif
        } else {
            networkSettings.mtu = NSNumber(value: mtu)
        }

        let (ipv4Addresses, ipv6Addresses) = addresses()
        let (ipv4IncludedRoutes, ipv6IncludedRoutes) = includedRoutes()
        let (ipv4ExcludedRoutes, ipv6ExcludedRoutes) = generateExcludedRoutes()

        let ipv4Settings = NEIPv4Settings(addresses: ipv4Addresses.map { $0.destinationAddress }, subnetMasks: ipv4Addresses.map { $0.destinationSubnetMask })
        ipv4Settings.includedRoutes = ipv4IncludedRoutes
        ipv4Settings.excludedRoutes = ipv4ExcludedRoutes
        networkSettings.ipv4Settings = ipv4Settings

        let ipv6Settings = NEIPv6Settings(addresses: ipv6Addresses.map { $0.destinationAddress }, networkPrefixLengths: ipv6Addresses.map { $0.destinationNetworkPrefixLength })
        ipv6Settings.includedRoutes = ipv6IncludedRoutes
        ipv6Settings.excludedRoutes = ipv6ExcludedRoutes
        networkSettings.ipv6Settings = ipv6Settings

        return networkSettings
    }

    private func addresses() -> ([NEIPv4Route], [NEIPv6Route]) {
        var ipv4Routes = [NEIPv4Route]()
        var ipv6Routes = [NEIPv6Route]()
        for addressRange in getInterfaceAddresses() {
            if addressRange.address is IPv4Address {
                ipv4Routes.append(NEIPv4Route(destinationAddress: "\(addressRange.address)", subnetMask: "\(addressRange.subnetMask())"))
            } else if addressRange.address is IPv6Address {
                /* Big fat ugly hack for broken iOS networking stack: the smallest prefix that will have
                 * any effect on iOS is a /120, so we clamp everything above to /120. This is potentially
                 * very bad, if various network parameters were actually relying on that subnet being
                 * intentionally small. TODO: talk about this with upstream iOS devs.
                 */
                ipv6Routes.append(NEIPv6Route(destinationAddress: "\(addressRange.address)", networkPrefixLength: NSNumber(value: min(120, addressRange.networkPrefixLength))))
            }
        }
        return (ipv4Routes, ipv6Routes)
    }

    private func includedRoutes() -> ([NEIPv4Route], [NEIPv6Route]) {
        var ipv4IncludedRoutes = [NEIPv4Route]()
        var ipv6IncludedRoutes = [NEIPv6Route]()

        // TODO: (randy) check if we need to make sure these does not overlap with excluded rotues
        for addressRange in getInterfaceAddresses() {
            if addressRange.address is IPv4Address {
                let route = NEIPv4Route(destinationAddress: "\(addressRange.maskedAddress())", subnetMask: "\(addressRange.subnetMask())")
                route.gatewayAddress = "\(addressRange.address)"
                ipv4IncludedRoutes.append(route)
            } else if addressRange.address is IPv6Address {
                let route = NEIPv6Route(destinationAddress: "\(addressRange.maskedAddress())", networkPrefixLength: NSNumber(value: addressRange.networkPrefixLength))
                route.gatewayAddress = "\(addressRange.address)"
                ipv6IncludedRoutes.append(route)
            }
        }

        for addressRange in getRoutes() {
            if addressRange.address is IPv4Address {
                ipv4IncludedRoutes.append(NEIPv4Route(
                    destinationAddress: "\(addressRange.address)",
                    subnetMask: "\(addressRange.subnetMask())")
                )
            } else if addressRange.address is IPv6Address {
                ipv6IncludedRoutes.append(NEIPv6Route(
                    destinationAddress: "\(addressRange.address)",
                    networkPrefixLength: NSNumber(value: addressRange.networkPrefixLength))
                )
            }
        }
        return (ipv4IncludedRoutes, ipv6IncludedRoutes)
    }

    private func generateExcludedRoutes() -> ([NEIPv4Route], [NEIPv6Route]) {
        var ipv4ExcludedRoutes = [NEIPv4Route]()
        var ipv6ExcludedRoutes = [NEIPv6Route]()

        for addressRange in getExcludedRoutes() {
            if addressRange.address is IPv4Address {
                ipv4ExcludedRoutes.append(NEIPv4Route(
                    destinationAddress: "\(addressRange.address)",
                    subnetMask: "\(addressRange.subnetMask())")
                )
            } else if addressRange.address is IPv6Address {
                ipv6ExcludedRoutes.append(NEIPv6Route(
                    destinationAddress: "\(addressRange.address)",
                    networkPrefixLength: NSNumber(value: addressRange.networkPrefixLength))
                )
            }
        }
        return (ipv4ExcludedRoutes, ipv6ExcludedRoutes)
    }

    private class func reresolveEndpoint(endpoint: Endpoint) -> EndpointResolutionResult {
        return Result { (endpoint, try endpoint.withReresolvedIP()) }
            .mapError { error -> DNSResolutionError in
                // swiftlint:disable:next force_cast
                return error as! DNSResolutionError
            }
    }
}
