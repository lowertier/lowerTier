import Darwin
import Foundation

// The Rust tests cover bounded queues. This fixture covers Swift pointer ownership and batching.
enum CoreFixture {
    static let lock = NSCondition()
    static let entered = DispatchSemaphore(value: 0)
    static var receiver: PacketReceiver?
    static var context: UnsafeMutableRawPointer?
    static var input: [Data] = []
    static var batchSizes: [Int] = []
    static var blocked = false
    static var stopped = false
}

@_cdecl("packet_tunnel_open")
func fixtureOpen(_ name: UnsafePointer<CChar>?, _ receiver: PacketReceiver?, _ context: UnsafeMutableRawPointer?, _ handle: UnsafeMutablePointer<UInt64>?) -> Int32 {
    CoreFixture.receiver = receiver
    CoreFixture.context = context
    handle?.pointee = 1
    return 0
}

@_cdecl("packet_tunnel_batch_capacity")
func fixtureCapacity() -> Int { 64 }

@_cdecl("packet_tunnel_send")
func fixtureSend(_ handle: UInt64, _ packets: UnsafePointer<PacketSlice>?, _ count: Int) -> Int32 {
    CoreFixture.lock.lock()
    defer { CoreFixture.lock.unlock() }
    if CoreFixture.blocked { CoreFixture.entered.signal() }
    while CoreFixture.blocked && !CoreFixture.stopped { CoreFixture.lock.wait() }
    if CoreFixture.stopped { return -1 }
    for packet in UnsafeBufferPointer(start: packets, count: count) {
        CoreFixture.input.append(Data(bytes: packet.data!, count: packet.length))
    }
    CoreFixture.batchSizes.append(count)
    return 0
}

@_cdecl("packet_tunnel_close")
func fixtureClose(_ handle: UInt64) -> Int32 {
    CoreFixture.lock.lock()
    CoreFixture.stopped = true
    CoreFixture.lock.broadcast()
    CoreFixture.lock.unlock()
    return 0
}

@main
struct PacketFlowTest {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) {
        guard condition() else {
            fputs("FAIL: \(message)\n", stderr)
            exit(1)
        }
    }

    static func main() throws {
        let complete = DispatchSemaphore(value: 0)
        let stopped = DispatchSemaphore(value: 0)
        var replies: [Data] = []
        var families: [NSNumber] = []
        let bridge = PacketBridge(deliver: { packets, protocols in
            replies.append(contentsOf: packets)
            families.append(contentsOf: protocols)
            return true
        }, fail: { error in
            fputs("Unexpected bridge error: \(error)\n", stderr)
            exit(1)
        })
        let attached = try bridge.start(instance: "fixture")
        require(attached, "The packet interface did not attach.")
        let packets = (0..<256).map { index -> Data in
            var bytes = [UInt8](repeating: UInt8(index % 256), count: 1280)
            bytes[0] = index % 2 == 0 ? 0x45 : 0x60
            return Data(bytes)
        }
        let protocols = (0..<256).map { NSNumber(value: $0 % 2 == 0 ? AF_INET : AF_INET6) }
        bridge.send(packets, protocols: protocols) { complete.signal() }
        require(complete.wait(timeout: .now() + 3) == .success, "The input batch did not complete.")
        CoreFixture.lock.lock()
        require(CoreFixture.input == packets, "The input payload changed or lost ordering.")
        require(CoreFixture.batchSizes == [64, 64, 64, 64], "The bridge did not preserve bounded batches.")
        CoreFixture.lock.unlock()
        let storage = packets.prefix(8).map { $0 as NSData }
        let slices = storage.map { PacketSlice(data: $0.bytes.assumingMemoryBound(to: UInt8.self), length: $0.length) }
        let result = withExtendedLifetime(storage) {
            slices.withUnsafeBufferPointer { CoreFixture.receiver!($0.baseAddress, $0.count, CoreFixture.context) }
        }
        require(result == 0, "The output callback failed.")
        require(replies == Array(packets.prefix(8)), "The output payload changed or lost ordering.")
        require(families == Array(protocols.prefix(8)), "The output address family changed.")
        CoreFixture.lock.lock()
        CoreFixture.blocked = true
        CoreFixture.lock.unlock()
        bridge.send([packets[0]], protocols: [protocols[0]]) { complete.signal() }
        require(CoreFixture.entered.wait(timeout: .now() + 3) == .success, "The blocked input did not start.")
        bridge.stop { stopped.signal() }
        require(stopped.wait(timeout: .now() + 3) == .success, "Stopping did not cancel blocked input.")
        require(complete.wait(timeout: .now() + 0.1) == .timedOut, "Stopped input resumed the OS read loop.")
        print("PASS: 256 ordered input packets, bounded batches, IPv4/IPv6 output, borrowed pointer lifetime, and stop cancellation.")
    }
}
