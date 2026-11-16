import Darwin
import Foundation

/// One pending OS batch waits for the core's bounded packet capacity.
final class PacketBridge {
    private let queue = DispatchQueue(label: "com.lowertier.packet-flow", qos: .userInitiated)
    private let lock = NSLock()
    private var handle: UInt64 = 0
    private let deliver: ([Data], [NSNumber]) -> Bool
    private let fail: (Error) -> Void

    init(deliver: @escaping ([Data], [NSNumber]) -> Bool, fail: @escaping (Error) -> Void) {
        self.deliver = deliver
        self.fail = fail
    }

    func start(instance: String) throws -> Bool {
        var opened: UInt64 = 0
        let result = instance.withCString {
            packet_tunnel_open($0, { packets, count, context in
                guard let packets, let context else { return -1 }
                let bridge = Unmanaged<PacketBridge>.fromOpaque(context).takeUnretainedValue()
                return bridge.receive(UnsafeBufferPointer(start: packets, count: count)) ? 0 : -1
            }, Unmanaged.passUnretained(self).toOpaque(), &opened)
        }
        if result == 1 { return false }
        guard result == 0 && opened != 0 else {
            throw TunnelError.message("The VPN core could not attach the packet interface.")
        }
        lock.lock()
        handle = opened
        lock.unlock()
        return true
    }

    private func currentHandle() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return handle
    }

    func send(_ packets: [Data], protocols: [NSNumber], completion: @escaping () -> Void) {
        queue.async {
            let handle = self.currentHandle()
            guard handle != 0 else { return }
            guard packets.count == protocols.count else {
                self.fail(TunnelError.message("The packet flow returned mismatched protocol metadata.")); return
            }
            let capacity = Int(packet_tunnel_batch_capacity())
            for offset in stride(from: 0, to: packets.count, by: capacity) {
                let end = min(offset + capacity, packets.count)
                for index in offset..<end {
                    let packet = packets[index]
                    let family = protocols[index].int32Value
                    guard let first = packet.first,
                          (first >> 4 == 4 && family == AF_INET) || (first >> 4 == 6 && family == AF_INET6) else {
                        self.fail(TunnelError.message("The packet flow returned an invalid IP family.")); return
                    }
                }
                // NSData keeps each borrowed pointer valid during the blocking FFI call.
                let storage = packets[offset..<end].map { $0 as NSData }
                let slices = storage.map { PacketSlice(data: $0.bytes.assumingMemoryBound(to: UInt8.self), length: $0.length) }
                let result = withExtendedLifetime(storage) {
                    slices.withUnsafeBufferPointer { packet_tunnel_send(handle, $0.baseAddress, $0.count) }
                }
                guard result == 0 else {
                    if self.currentHandle() != 0 {
                        self.fail(TunnelError.message("The VPN packet input stopped."))
                    }
                    return
                }
            }
            if self.currentHandle() != 0 { completion() }
        }
    }

    private func receive(_ batch: UnsafeBufferPointer<PacketSlice>) -> Bool {
        var packets: [Data] = []
        var protocols: [NSNumber] = []
        packets.reserveCapacity(batch.count)
        protocols.reserveCapacity(batch.count)
        for packet in batch {
            guard let bytes = packet.data, packet.length >= 20, packet.length <= 1280 else { return rejectOutput() }
            let version = bytes.pointee >> 4
            guard version == 4 || (version == 6 && packet.length >= 40) else { return rejectOutput() }
            packets.append(Data(bytes: bytes, count: packet.length))
            protocols.append(NSNumber(value: version == 4 ? AF_INET : AF_INET6))
        }
        guard deliver(packets, protocols) else { return rejectOutput() }
        return true
    }

    private func rejectOutput() -> Bool {
        fail(TunnelError.message("iOS rejected the VPN packet output."))
        return false
    }

    func stop(completion: @escaping () -> Void) {
        lock.lock()
        let closing = handle
        handle = 0
        lock.unlock()
        // Closing cancels blocked input and waits for the final borrowed output callback.
        if closing != 0 { _ = packet_tunnel_close(closing) }
        completion()
    }
}
