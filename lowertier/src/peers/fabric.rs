use crate::tunnel::batch::PacketBatch;
use crate::tunnel::packet_def::ZCPacket;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FabricPayloadKind {
    Ip,
    Ethernet,
}

pub struct FabricPacket {
    payload_kind: FabricPayloadKind,
    packet: ZCPacket,
}

impl FabricPacket {
    pub fn new(payload_kind: FabricPayloadKind, packet: ZCPacket) -> Self {
        Self {
            payload_kind,
            packet,
        }
    }

    pub fn payload_kind(&self) -> FabricPayloadKind {
        self.payload_kind
    }

    pub fn into_packet(self) -> ZCPacket {
        self.packet
    }
}

pub struct FabricBatch {
    payload_kind: FabricPayloadKind,
    packets: PacketBatch,
}

impl FabricBatch {
    pub fn new(payload_kind: FabricPayloadKind, packets: PacketBatch) -> Self {
        Self {
            payload_kind,
            packets,
        }
    }

    pub fn singleton(packet: FabricPacket) -> Self {
        Self::new(
            packet.payload_kind(),
            PacketBatch::singleton(packet.into_packet()),
        )
    }

    pub fn payload_kind(&self) -> FabricPayloadKind {
        self.payload_kind
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn shape(&self) -> (usize, usize) {
        (self.packets.len(), self.packets.buffer_byte_len())
    }

    pub fn into_packets(self) -> PacketBatch {
        self.packets
    }
}
