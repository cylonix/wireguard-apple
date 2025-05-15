// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Security

class Keychain {
    static func openReference(called ref: Data) -> String? {
        var result: CFTypeRef?
        let ret = SecItemCopyMatching([kSecValuePersistentRef: ref,
                                        kSecReturnData: true] as CFDictionary,
                                       &result)
        if ret != errSecSuccess || result == nil {
            wg_log(.error, message: "Unable to open config from keychain: \(ret)")
            return nil
        }
        guard let data = result as? Data else { return nil }
        return String(data: data, encoding: String.Encoding.utf8)
    }

    static func makeReference(containing value: String, called name: String, previouslyReferencedBy oldRef: Data? = nil) -> Data? {
        var ret: OSStatus
        guard var bundleIdentifier = Bundle.main.bundleIdentifier else {
            wg_log(.error, staticMessage: "Unable to determine bundle identifier")
            return nil
        }
        if bundleIdentifier.hasSuffix(".network-extension") {
            bundleIdentifier.removeLast(".network-extension".count)
        }
        let itemLabel = "WireGuard Tunnel: \(name)"
        var items: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
                                    kSecAttrLabel: itemLabel,
                                    kSecAttrAccount: name + ": " + UUID().uuidString,
                                    kSecAttrDescription: "wg-quick(8) config",
                                    kSecAttrService: bundleIdentifier,
                                    kSecValueData: value.data(using: .utf8) as Any,
                                    kSecReturnPersistentRef: true]

        #if os(iOS)
        items[kSecAttrAccessGroup] = FileManager.appGroupId
        items[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlock
        #elseif os(macOS)
        items[kSecAttrSynchronizable] = false
        items[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        guard let extensionPath = getExtensionPath() else {
            wg_log(.error, staticMessage: "Unable to determine app extension path")
            return nil
        }
        wg_log(.debug, message: "Found network extension at: \(extensionPath)")

        var extensionApp: SecTrustedApplication?
        var mainApp: SecTrustedApplication?
        ret = SecTrustedApplicationCreateFromPath(extensionPath, &extensionApp)
        if ret != kOSReturnSuccess || extensionApp == nil {
            wg_log(.error, message: "Unable to create keychain extension trusted application object: \(ret)")
            return nil
        }
        ret = SecTrustedApplicationCreateFromPath(nil, &mainApp)
        if ret != errSecSuccess || mainApp == nil {
            wg_log(.error, message: "Unable to create keychain local trusted application object: \(ret)")
            return nil
        }
        var access: SecAccess?
        ret = SecAccessCreate(itemLabel as CFString, [extensionApp!, mainApp!] as CFArray, &access)
        if ret != errSecSuccess || access == nil {
            wg_log(.error, message: "Unable to create keychain ACL object: \(ret)")
            return nil
        }
        items[kSecAttrAccess] = access!
        if let accessGroup = getKeychainAccessGroup() {
            wg_log(.info, message: "Using ios style keychain for macos")
            items.removeValue(forKey: kSecAttrAccess)
            items[kSecAttrAccessGroup] = accessGroup
            items[kSecUseDataProtectionKeychain] = true
            items[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlock
        } else {
            wg_log(.info, message: "Using macos old style keychain")
        }
        #else
        #error("Unimplemented")
        #endif

        var ref: CFTypeRef?
        ret = SecItemAdd(items as CFDictionary, &ref)
        if ret != errSecSuccess || ref == nil {
            wg_log(.error, message: "Unable to add config to keychain: \(ret)")
            return nil
        }
        if let oldRef = oldRef {
            deleteReference(called: oldRef)
        }
        return ref as? Data
    }

    static func deleteReference(called ref: Data) {
        let ret = SecItemDelete([kSecValuePersistentRef: ref] as CFDictionary)
        if ret != errSecSuccess {
            wg_log(.error, message: "Unable to delete config from keychain: \(ret)")
        }
    }

    static func deleteReferences(except whitelist: Set<Data>) {
        var result: CFTypeRef?
        let ret = SecItemCopyMatching([kSecClass: kSecClassGenericPassword,
                                       kSecAttrService: Bundle.main.bundleIdentifier as Any,
                                       kSecMatchLimit: kSecMatchLimitAll,
                                       // Make sure to keep kSecAttrDescription otherwise
                                       // it will delete items set by the network extension
                                       kSecAttrDescription: "wg-quick(8) config",
                                       kSecReturnPersistentRef: true] as CFDictionary,
                                      &result)
        if ret != errSecSuccess || result == nil {
            return
        }
        guard let items = result as? [Data] else { return }
        for item in items {
            if !whitelist.contains(item) {
                wg_log(.info, message: "Deleting keychain item \(item)")
                deleteReference(called: item)
            }
        }
    }

    static func verifyReference(called ref: Data) -> Bool {
        return SecItemCopyMatching([kSecValuePersistentRef: ref] as CFDictionary,
                                   nil) != errSecItemNotFound
    }
}

extension Keychain {
    private static let keychainAccessGroupInfoDictionaryKey = "io.cylonix.keychain_access_group_id"
    private static func getKeychainAccessGroup() -> String? {
        return Bundle.main.object(forInfoDictionaryKey: keychainAccessGroupInfoDictionaryKey) as? String
    }

    private static func getExtensionPathFromPluginsDirectory() -> String? {
        guard let pluginsURL = Bundle.main.builtInPlugInsURL else {
            wg_log(.error, staticMessage: "Unable to access plugins directory")
            return nil
        }

        // Debug: List all plugins and their Info.plist contents
        if let contents = try? FileManager.default.contentsOfDirectory(at: pluginsURL, includingPropertiesForKeys: nil) {
            wg_log(.debug, message: "Found \(contents.count) items in plugins directory:")
            for url in contents {
                if let bundle = Bundle(url: url) {
                    wg_log(.debug, message: "Plugin: \(url.lastPathComponent)")
                    if let info = bundle.infoDictionary {
                        for (key, value) in info {
                            wg_log(.debug, message: "  \(key): \(value)")
                        }
                    }
                }
            }
        }

        let networkExtension = try? FileManager.default.contentsOfDirectory(
            at: pluginsURL,
            includingPropertiesForKeys: nil
        ).first { url in
            url.pathExtension == "appex" &&
                (Bundle(url: url)?.infoDictionary?["NSExtension"] as? [String: String])?["NSExtensionPointIdentifier"] ==
                    "com.apple.networkextension.packet-tunnel"
        }
        return networkExtension?.path
    }

    private static func getExtensionPath() -> String? {
        if let extensionPath = getExtensionPathFromPluginsDirectory() {
            wg_log(.debug, message: "Found network extension in plugin directory at: \(extensionPath)")
            return extensionPath
        }
        wg_log(.error, staticMessage: "Unable to find network extension in plugins directory")
        return Bundle.main.builtInPlugInsURL?.appendingPathComponent("CylonixNetworkExtension.appex", isDirectory: true).path
    }
}
