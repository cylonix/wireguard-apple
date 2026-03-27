import Foundation

enum PacketTunnelMessage {
  static let prefix = "io.cylonix.sase.tunnelMessage."
  static func messageFile(channel: String)  -> String { "\(channel).json" }
  static func responseFile(channel: String) -> String { "\(channel).response.json" }
  static let share = prefix + "share"
  static let tailchat = prefix + "tailchat"
  static let peerMessage = prefix + "peerMessage"
}

enum PacketTunnelNotification {
  static let chatsReceived = "io.cylonix.sase.tunnelNotification.chatsReceived"
  static let chatStatus = "io.cylonix.sase.tunnelNotification.chatStatus"
  static let filesWaiting = "io.cylonix.sase.tunnelNotification.filesWaiting"
  static let ipnNotify = "io.cylonix.sase.tunnelNotification.ipnNotify"
  static let peerMessageReceived = "io.cylonix.sase.tunnelNotification.peerMessageReceived"
  static let userNotification = "io.cylonix.sase.tunnelNotification.userNotification"
}

enum PacketTunnelUserDefaultsKey {
    static let chatsReceived = "ChatsReceived"
    static let chatStatus = "ChatStatus"
    static let filesWaiting = "FilesWaiting"
    static let ipnNotify = "IpnNotify"
    static let peerMessageReceived = "PeerMessageReceived"
    static let autoSavedFilesByTransferID = "AutoSavedFilesByTransferID"
}
