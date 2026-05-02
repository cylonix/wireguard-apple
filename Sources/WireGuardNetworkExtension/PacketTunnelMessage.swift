import Foundation

enum PacketTunnelMessage {
  static let prefix = "io.cylonix.sase.tunnelMessage."
  static func messageFile(channel: String)  -> String { "\(channel).json" }
  static func responseFile(channel: String) -> String { "\(channel).response.json" }
  static let share = prefix + "share"
  static let tailchat = prefix + "tailchat"
  static let peerMessage = prefix + "peerMessage"
  static let backendLivenessProbe = prefix + "backendLivenessProbe"
}

enum PacketTunnelNotification {
  static let chatsReceived = "io.cylonix.sase.tunnelNotification.chatsReceived"
  static let chatStatus = "io.cylonix.sase.tunnelNotification.chatStatus"
  static let filesWaiting = "io.cylonix.sase.tunnelNotification.filesWaiting"
  static let ipnNotify = "io.cylonix.sase.tunnelNotification.ipnNotify"
  static let peerMessageReceived = "io.cylonix.sase.tunnelNotification.peerMessageReceived"
  static let userNotification = "io.cylonix.sase.tunnelNotification.userNotification"
  static let backendLivenessProbeResponse = "io.cylonix.sase.tunnelNotification.backendLivenessProbeResponse"
}

enum PacketTunnelUserDefaultsKey {
    static let chatsReceived = "ChatsReceived"
    static let chatStatus = "ChatStatus"
    static let filesWaiting = "FilesWaiting"
    static let ipnNotify = "IpnNotify"
    static let peerMessageReceived = "PeerMessageReceived"
    static let autoSavedFilesByTransferID = "AutoSavedFilesByTransferID"
    static let notificationPreviewEnabled = "NotificationPreviewEnabled"
    static let backendLivenessProbeRequestID = "BackendLivenessProbeRequestID"
    static let backendLivenessProbeRequestAtUs = "BackendLivenessProbeRequestAtUs"
    static let backendLivenessProbeResponseID = "BackendLivenessProbeResponseID"
    static let backendLivenessProbeResponseAtUs = "BackendLivenessProbeResponseAtUs"
    static let backendLivenessProbeAlive = "BackendLivenessProbeAlive"
    static let backendLivenessProbeBackendState = "BackendLivenessProbeBackendState"
    static let backendLivenessProbeError = "BackendLivenessProbeError"
    static let backendLivenessProbeProviderStopping = "BackendLivenessProbeProviderStopping"
}
