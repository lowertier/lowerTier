import Foundation

// The host fixture replaces Tauri IPC. The production iOS build uses the real Tauri module.
open class Plugin: NSObject {}

@objc public class Invoke: NSObject {
    private let args: String
    private let reply: ([String: Any]) -> Void
    private let failure: (String) -> Void
    private var completed = false

    public init(args: String, reply: @escaping ([String: Any]) -> Void, failure: @escaping (String) -> Void) {
        self.args = args
        self.reply = reply
        self.failure = failure
    }

    public func getRawArgs() -> String { args }

    public func resolve(_ value: [String: Any]) {
        precondition(!completed, "The invocation completed more than once.")
        completed = true
        reply(value)
    }

    public func reject(_ message: String) {
        precondition(!completed, "The invocation completed more than once.")
        completed = true
        failure(message)
    }
}
