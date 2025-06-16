import Foundation
import Security

extension Keychain {
    private enum Constants {
        static let labelPrefix = "Cylonix: "
    }

    private static func getKeychainAccessGroup() -> String? {
        let keychainAccessGroupInfoDictionaryKey = "io.cylonix.keychain_access_group_id"
        return Bundle.main.object(forInfoDictionaryKey: keychainAccessGroupInfoDictionaryKey) as? String
    }

    static func getItem(key: String) -> String {
        guard !key.isEmpty else {
            let msg = "Key cannot be empty"
            wg_log(.error, message: msg)
            return "ERROR: \(msg)"
        }

        wg_log(.info, message: "Keychain getItem: get item key: \(key)")

        guard var bundleIdentifier = Bundle.main.bundleIdentifier else {
            let msg = "Unable to determine bundle identifier"
            wg_log(.error, message: msg)
            return "ERROR: \(msg)"
        }

        // Normalize bundle ID by removing .network-extension suffix
        if bundleIdentifier.hasSuffix(".network-extension") {
            bundleIdentifier.removeLast(".network-extension".count)
        }

        let itemLabel = Constants.labelPrefix + key
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: itemLabel,
            kSecAttrAccount: key,
            kSecAttrService: bundleIdentifier,
            kSecReturnData: true,
        ]

        #if os(iOS)
            query[kSecAttrAccessGroup] = FileManager.appGroupId
        #elseif os(macOS)
            guard let accessGroup = getKeychainAccessGroup() else {
                let msg = "Unable to determine access group"
                wg_log(.error, message: msg)
                return "ERROR: \(msg)"
            }
            query[kSecAttrAccessGroup] = accessGroup
            query[kSecUseDataProtectionKeychain] = true
        #endif

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return "keychain item not found"
        }
        guard status == errSecSuccess, let data = result as? Data else {
            let msg = "Unable to get item from keychain: \(status)"
            wg_log(.error, message: msg)
            return "ERROR: \(msg)"
        }
        guard let value = String(data: data, encoding: .utf8) else {
            let msg = "Invalid UTF-8 data"
            wg_log(.error, message: msg)
            return "ERROR: \(msg)"
        }

        wg_log(.info, message: "Keychain getItem: got item key: \(key) value[\(value.count)]: \(shortString(value))")
        return "SUCCESS: \(value)"
    }

    static private func shortString(_ str: String) -> String {
        let maxLength = 20
        if str.count > maxLength {
            let index = str.index(str.startIndex, offsetBy: maxLength)
            return String(str[..<index]) + "..."
        }
        return str
    }

    static func setItem(key: String, value: String) -> String {
        guard !key.isEmpty else {
            let msg = "Key cannot be empty"
            wg_log(.error, message: msg)
            return "ERROR: \(msg)"
        }
        guard var bundleIdentifier = Bundle.main.bundleIdentifier else {
            let msg = "Unable to determine bundle identifier"
            wg_log(.error, message: msg)
            return "ERROR: \(msg)"
        }
        wg_log(.info, message: "Keychain setItem: set item key: \(key) value: \(shortString(value))")

        // Normalize bundle ID by removing .network-extension suffix
        if bundleIdentifier.hasSuffix(".network-extension") {
            bundleIdentifier.removeLast(".network-extension".count)
        }

        // Delete existing items
        var deleteQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: key,
            kSecAttrService: bundleIdentifier,
        ]
        #if os(iOS)
            deleteQuery[kSecAttrAccessGroup] = FileManager.appGroupId
        #elseif os(macOS)
            guard let accessGroup = getKeychainAccessGroup() else {
                let msg = "Keychain setItem: Unable to determine access group"
                wg_log(.error, message: msg)
                return "ERROR: \(msg)"
            }
            deleteQuery[kSecUseDataProtectionKeychain] = true
        #endif
        let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
        if deleteStatus != errSecSuccess && deleteStatus != errSecItemNotFound {
            let msg = "Keychain setItem: Unable to delete item for service \(bundleIdentifier): \(deleteStatus)"
            wg_log(.error, message: msg)
        }

        let itemLabel = Constants.labelPrefix + key
        var items: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrLabel: itemLabel,
            kSecAttrAccount: key,
            kSecAttrDescription: "Cylonix keystore: " + key,
            kSecAttrService: bundleIdentifier,
            kSecValueData: value.data(using: .utf8) as Any,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock,
        ]

        #if os(iOS)
            items[kSecAttrAccessGroup] = FileManager.appGroupId
        #elseif os(macOS)
            items[kSecAttrAccessGroup] = accessGroup
            items[kSecUseDataProtectionKeychain] = true
            items[kSecAttrSynchronizable] = false
            wg_log(.info, message: "Using ios style keychain for macOS. AccessGroup=\(accessGroup)")
        #endif

        let ret = SecItemAdd(items as CFDictionary, nil)
        if ret != errSecSuccess {
            let msg = "Unable to add item to keychain: \(ret)"
            wg_log(.error, message: msg)
            return "ERROR: \(msg)"
        }
        let msg = "SUCCESS: ADD ITEM DONE"
        wg_log(.info, message: msg)
        return msg
    }

    #if os(macOS)
        static func clearOldKeychainItems() {
            guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
                wg_log(.error, message: "Unable to determine bundle identifier for cleanup")
                return
            }
            var service = bundleIdentifier
            if service.hasSuffix(".network-extension") {
                service.removeLast(".network-extension".count)
            }

            let query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
            ]
            let ret = SecItemDelete(query as CFDictionary)
            if ret != errSecSuccess, ret != errSecItemNotFound {
                wg_log(.error, message: "Failed to delete old items for service \(service): \(ret)")
            }
        }
    #endif
}
