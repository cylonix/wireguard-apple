import Foundation

enum PacketTunnelMessage {
  static let prefix = "io.cylonix.sase.tunnelMessage."
  static func messageFile(channel: String)  -> String { "\(channel).json" }
  static func responseFile(channel: String) -> String { "\(channel).response.json" }
  static let share = prefix + "share"
  static let tailchat = prefix + "tailchat"
}

enum PacketTunnelNotification {
  static let chatsReceived = "io.cylonix.sase.tunnelNotification.chatsReceived"
  static let filesWaiting = "io.cylonix.sase.tunnelNotification.filesWaiting"
  static let ipnNotify = "io.cylonix.sase.tunnelNotification.ipnNotify"
  static let userNotification = "io.cylonix.sase.tunnelNotification.userNotification"
}

enum PacketTunnelUserDefaultsKey {
    static let chatsReceived = "ChatsReceived"
    static let filesWaiting = "FilesWaiting"
    static let ipnNotify = "IpnNotify"
}