use std::collections::HashMap;

use prost::{Message as _, length_delimiter_len};

use quanta::Instant;

use crate::{
    common::{PeerId, compressor::DefaultCompressor},
    proto::{
        common::{CompressionAlgoPb, RpcCompressionInfo, RpcDescriptor, RpcPacket},
        rpc_types::error::Error,
    },
    tunnel::packet_def::{CompressorAlgo, PacketType, TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType},
};

use super::RpcTransactId;

// Budget the final UDP payload size on the wire for peer RPC over `udp://`.
// This includes LowTier's UDP tunnel header, peer header, and reserved tail
// space for encryption/compression metadata, but excludes the outer IP header.
const RPC_PACKET_UDP_PAYLOAD_BUDGET: usize = 1300;

/// Maximum logical RPC body after fragment reassembly or decompression.
pub(crate) const MAX_RPC_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_RPC_PIECES: u32 = 32 * 1024;
// Account for the sparse map slot retained for each fragment.
const RPC_MERGER_MAP_ENTRY_OVERHEAD: usize = 64;
// Account for the immutable envelope retained once per fragmented transaction.
const RPC_MERGER_ENVELOPE_OVERHEAD: usize = 128;

pub const fn supported_rpc_compression() -> CompressionAlgoPb {
    #[cfg(feature = "zstd")]
    {
        CompressionAlgoPb::Zstd
    }
    #[cfg(not(feature = "zstd"))]
    {
        CompressionAlgoPb::None
    }
}

/// Return the logical body size before a request enters RPC execution.
///
/// The size comes from the bounded zstd frame header when compression is used.
/// This avoids decompression before admission and prevents a compressed body
/// from bypassing the execution memory budget.
pub(crate) fn logical_body_size(packet: &RpcPacket) -> Result<usize, Error> {
    if packet.body.len() > MAX_RPC_BODY_BYTES {
        return Err(Error::MalformatRpcPacket(format!(
            "RPC body is too large: {} bytes",
            packet.body.len()
        )));
    }

    let Some(compression_info) = packet.compression_info else {
        return Ok(packet.body.len());
    };
    let compression_algo = CompressionAlgoPb::try_from(compression_info.algo).map_err(|_| {
        Error::MalformatRpcPacket(format!(
            "unknown RPC compression algorithm: {}",
            compression_info.algo
        ))
    })?;

    match compression_algo {
        CompressionAlgoPb::None => Ok(packet.body.len()),
        #[cfg(feature = "zstd")]
        CompressionAlgoPb::Zstd => {
            let frame_size =
                zstd::zstd_safe::get_frame_content_size(&packet.body).map_err(|error| {
                    Error::MalformatRpcPacket(format!("invalid zstd RPC frame: {error}"))
                })?;
            let Some(frame_size) = frame_size else {
                return Err(Error::MalformatRpcPacket(
                    "zstd RPC frame has no bounded content size".to_string(),
                ));
            };
            let frame_size = usize::try_from(frame_size).map_err(|_| {
                Error::MalformatRpcPacket(
                    "zstd RPC frame size does not fit memory limits".to_string(),
                )
            })?;
            if frame_size > MAX_RPC_BODY_BYTES {
                return Err(Error::MalformatRpcPacket(format!(
                    "decompressed RPC body is too large: {frame_size} bytes"
                )));
            }
            Ok(frame_size)
        }
        #[cfg(not(feature = "zstd"))]
        CompressionAlgoPb::Zstd => Err(Error::MalformatRpcPacket(
            "zstd RPC compression is not available".to_string(),
        )),
        _ => Err(Error::MalformatRpcPacket(
            "invalid RPC compression algorithm".to_string(),
        )),
    }
}

pub async fn compress_packet(
    accepted_compression_algo: CompressionAlgoPb,
    content: &[u8],
) -> Result<(Vec<u8>, CompressionAlgoPb), Error> {
    let compressor = DefaultCompressor::new();
    let algo = accepted_compression_algo
        .try_into()
        .unwrap_or(CompressorAlgo::None);
    let compressed = compressor.compress_raw(content, algo)?;
    if compressed.len() >= content.len() {
        Ok((content.to_vec(), CompressionAlgoPb::None))
    } else {
        Ok((compressed, algo.try_into().unwrap()))
    }
}

pub async fn decompress_packet(
    compression_algo: CompressionAlgoPb,
    content: &[u8],
) -> Result<Vec<u8>, Error> {
    let compressor = DefaultCompressor::new();
    let algo = compression_algo.try_into()?;
    if content.len() > MAX_RPC_BODY_BYTES {
        return Err(Error::MalformatRpcPacket(format!(
            "compressed RPC body is too large: {} bytes",
            content.len()
        )));
    }
    #[cfg(feature = "zstd")]
    if matches!(algo, CompressorAlgo::ZstdDefault) {
        let frame_size = zstd::zstd_safe::get_frame_content_size(content).map_err(|error| {
            Error::MalformatRpcPacket(format!("invalid zstd RPC frame: {error}"))
        })?;
        let Some(frame_size) = frame_size else {
            return Err(Error::MalformatRpcPacket(
                "zstd RPC frame has no bounded content size".to_string(),
            ));
        };
        if frame_size > MAX_RPC_BODY_BYTES as u64 {
            return Err(Error::MalformatRpcPacket(format!(
                "decompressed RPC body is too large: {frame_size} bytes"
            )));
        }
        let frame_size = usize::try_from(frame_size).map_err(|_| {
            Error::MalformatRpcPacket("zstd RPC frame size does not fit memory limits".to_string())
        })?;
        return zstd::bulk::decompress(content, frame_size)
            .map_err(|error| Error::ExecutionError(error.into()));
    }
    let decompressed = compressor.decompress_raw(content, algo)?;
    if decompressed.len() > MAX_RPC_BODY_BYTES {
        return Err(Error::MalformatRpcPacket(format!(
            "decompressed RPC body is too large: {} bytes",
            decompressed.len()
        )));
    }
    Ok(decompressed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FragmentEnvelope {
    from_peer: PeerId,
    to_peer: PeerId,
    descriptor: Option<RpcDescriptor>,
    is_request: bool,
    total_pieces: u32,
    transaction_id: i64,
    trace_id: i32,
}

impl FragmentEnvelope {
    fn from_packet(packet: &RpcPacket) -> Self {
        Self {
            from_peer: packet.from_peer,
            to_peer: packet.to_peer,
            descriptor: packet.descriptor.clone(),
            is_request: packet.is_request,
            total_pieces: packet.total_pieces,
            transaction_id: packet.transaction_id,
            trace_id: packet.trace_id,
        }
    }

    fn matches(&self, packet: &RpcPacket) -> bool {
        self == &Self::from_packet(packet)
    }
}

pub(crate) struct PacketMerger {
    first_envelope: Option<FragmentEnvelope>,
    first_compression_info: Option<RpcCompressionInfo>,
    compression_info_known: bool,
    pieces: HashMap<u32, RpcPacket>,
    body_bytes: usize,
    retained_bytes: usize,
    last_updated: Instant,
}

impl Default for PacketMerger {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketMerger {
    pub fn new() -> Self {
        Self {
            first_envelope: None,
            first_compression_info: None,
            compression_info_known: false,
            pieces: HashMap::new(),
            body_bytes: 0,
            retained_bytes: 0,
            last_updated: Instant::now(),
        }
    }

    fn compression_is_legal(packet: &RpcPacket) -> bool {
        packet.piece_idx == 0 || packet.compression_info.is_none()
    }

    fn try_merge_pieces(&self) -> Option<RpcPacket> {
        let Some(first_envelope) = self.first_envelope.as_ref() else {
            return None;
        };
        if self.pieces.is_empty() {
            return None;
        }

        let total_pieces = first_envelope.total_pieces;
        if self.pieces.len() != total_pieces as usize {
            return None;
        }
        for piece_idx in 0..total_pieces {
            let Some(p) = self.pieces.get(&piece_idx) else {
                return None;
            };
            // Some piece is missing.
            if p.total_pieces == 0 || p.piece_idx != piece_idx {
                return None;
            }
            if !first_envelope.matches(p) || !Self::compression_is_legal(p) {
                return None;
            }
        }

        // all pieces are received
        let mut body = Vec::with_capacity(self.body_bytes);
        for piece_idx in 0..total_pieces {
            let p = self
                .pieces
                .get(&piece_idx)
                .expect("piece count was checked");
            body.extend_from_slice(&p.body);
        }

        // Piece zero carries the complete compression metadata.
        let mut tmpl_packet = self.pieces.get(&0)?.clone();
        tmpl_packet.total_pieces = 1;
        tmpl_packet.piece_idx = 0;
        tmpl_packet.body = body;

        Some(tmpl_packet)
    }

    pub fn feed(&mut self, rpc_packet: RpcPacket) -> Result<Option<RpcPacket>, Error> {
        let total_pieces = rpc_packet.total_pieces;
        let piece_idx = rpc_packet.piece_idx;

        // for compatibility with old version
        if total_pieces == 0 && piece_idx == 0 {
            if rpc_packet.body.len() > MAX_RPC_BODY_BYTES {
                return Err(Error::MalformatRpcPacket(format!(
                    "unfragmented RPC body is too large: {} bytes",
                    rpc_packet.body.len()
                )));
            }
            return Ok(Some(rpc_packet));
        }

        if total_pieces == 0 {
            return Err(Error::MalformatRpcPacket(
                "fragmented RPC packet has zero total_pieces".to_owned(),
            ));
        }

        if rpc_packet.descriptor.is_none() {
            return Err(Error::MalformatRpcPacket(
                "descriptor is missing".to_owned(),
            ));
        }

        if !Self::compression_is_legal(&rpc_packet) {
            return Err(Error::MalformatRpcPacket(
                "compression metadata is only allowed on piece zero".to_owned(),
            ));
        }

        if total_pieces > MAX_RPC_PIECES {
            return Err(Error::MalformatRpcPacket(format!(
                "total_pieces is invalid: {}",
                total_pieces
            )));
        }

        if piece_idx >= total_pieces {
            return Err(Error::MalformatRpcPacket(
                "piece_idx >= total_pieces".to_owned(),
            ));
        }

        let envelope = FragmentEnvelope::from_packet(&rpc_packet);
        if let Some(first_envelope) = self.first_envelope.as_ref() {
            if !first_envelope.matches(&rpc_packet) {
                return Err(Error::MalformatRpcPacket(
                    "RPC fragment envelope does not match the first fragment".to_owned(),
                ));
            }
        } else {
            self.first_envelope = Some(envelope);
            tracing::trace!(?rpc_packet, "got first piece");
        }

        if rpc_packet.piece_idx == 0 {
            if self.compression_info_known
                && self.first_compression_info != rpc_packet.compression_info
            {
                return Err(Error::MalformatRpcPacket(
                    "piece zero compression metadata changed".to_owned(),
                ));
            }
            self.first_compression_info = rpc_packet.compression_info;
            self.compression_info_known = true;
        }

        if let Some(piece) = self.pieces.get(&piece_idx) {
            if piece.body != rpc_packet.body
                || piece.compression_info != rpc_packet.compression_info
            {
                return Err(Error::MalformatRpcPacket(
                    "duplicate RPC fragment has a different body".to_owned(),
                ));
            }
            self.last_updated = Instant::now();
            return Ok(self.try_merge_pieces());
        }

        let new_body_bytes = self
            .body_bytes
            .checked_add(rpc_packet.body.len())
            .ok_or_else(|| Error::MalformatRpcPacket("RPC body size overflow".to_owned()))?;
        if new_body_bytes > MAX_RPC_BODY_BYTES {
            return Err(Error::MalformatRpcPacket(format!(
                "reassembled RPC body is too large: {new_body_bytes} bytes"
            )));
        }
        self.body_bytes = new_body_bytes;
        let retained_piece_bytes = rpc_packet
            .encoded_len()
            .checked_add(RPC_MERGER_MAP_ENTRY_OVERHEAD)
            .and_then(|bytes| {
                if self.pieces.is_empty() {
                    bytes.checked_add(RPC_MERGER_ENVELOPE_OVERHEAD)
                } else {
                    Some(bytes)
                }
            })
            .ok_or_else(|| Error::MalformatRpcPacket("RPC retained size overflow".to_owned()))?;
        self.retained_bytes = self
            .retained_bytes
            .checked_add(retained_piece_bytes)
            .ok_or_else(|| Error::MalformatRpcPacket("RPC retained size overflow".to_owned()))?;
        self.pieces.insert(piece_idx, rpc_packet);

        self.last_updated = Instant::now();

        Ok(self.try_merge_pieces())
    }

    pub(crate) fn last_updated(&self) -> Instant {
        self.last_updated
    }

    pub(crate) fn retained_body_bytes(&self) -> usize {
        self.body_bytes
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub(crate) fn reservation_bytes(packet: &RpcPacket, new_transaction: bool) -> Option<usize> {
        packet
            .encoded_len()
            .checked_add(RPC_MERGER_MAP_ENTRY_OVERHEAD)?
            .checked_add(
                new_transaction
                    .then_some(RPC_MERGER_ENVELOPE_OVERHEAD)
                    .unwrap_or(0),
            )
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.first_envelope.is_none()
    }
}

pub struct BuildRpcPacketArgs<'a> {
    pub from_peer: PeerId,
    pub to_peer: PeerId,
    pub rpc_desc: RpcDescriptor,
    pub transaction_id: RpcTransactId,
    pub is_req: bool,
    pub content: &'a [u8],
    pub trace_id: i32,
    pub compression_info: RpcCompressionInfo,
}

// Fixed transport overhead for peer RPC carried by LowTier's UDP tunnel:
//
//   UDP payload budget
//   +-------------------------------------------------------------------------+
//   | LowTier UDP tunnel hdr | PeerManager hdr | RpcPacket bytes | tail room |
//   +-------------------------------------------------------------------------+
//   |<------ ZCPacketType::UDP payload_offset ------>|<-- TAIL_RESERVED_SIZE -->|
//
// `udp_rpc_tunnel_overhead()` is everything except `RpcPacket bytes`.
fn udp_rpc_tunnel_overhead() -> usize {
    ZCPacketType::UDP.get_packet_offsets().payload_offset + TAIL_RESERVED_SIZE
}

// Maximum encoded RpcPacket size we can admit before adding it to a UDP tunnel.
// This budget excludes the outer UDP/IP headers because the caller only controls
// the LowTier payload carried inside the UDP datagram.
fn max_rpc_packet_encoded_len_for_udp() -> usize {
    RPC_PACKET_UDP_PAYLOAD_BUDGET.saturating_sub(udp_rpc_tunnel_overhead())
}

// Build one logical RpcPacket piece. This is reused both for the actual output
// packets and for sizing templates that estimate worst-case protobuf overhead.
fn build_rpc_piece(
    args: &BuildRpcPacketArgs<'_>,
    total_pieces: u32,
    piece_idx: u32,
    body: &[u8],
) -> RpcPacket {
    RpcPacket {
        from_peer: args.from_peer,
        to_peer: args.to_peer,
        // Keep the descriptor on every piece so authorization can run before
        // a fragmented request enters the merger.
        descriptor: Some(args.rpc_desc.clone()),
        is_request: args.is_req,
        total_pieces,
        piece_idx,
        transaction_id: args.transaction_id,
        body: body.to_vec(),
        trace_id: args.trace_id,
        compression_info: if piece_idx == 0 {
            Some(args.compression_info)
        } else {
            None
        },
    }
}

fn pick_piece_len_for_budget(
    base_encoded_len_without_body: usize,
    remaining: usize,
    max_encoded_len: usize,
) -> usize {
    if remaining == 0 {
        return 0;
    }

    // Minimum non-empty body field encoding cost:
    //   body tag (1 byte) + body length (1 byte) + body data (1 byte)
    if base_encoded_len_without_body + 3 > max_encoded_len {
        tracing::warn!(
            base_encoded_len_without_body,
            max_encoded_len,
            "rpc metadata exceeds udp payload budget; falling back to a minimal piece"
        );
        return 1;
    }

    // `budget` is what remains for the protobuf `body` field after all fixed
    // RpcPacket metadata has been accounted for.
    let budget = max_encoded_len - base_encoded_len_without_body;
    // Reserve the bytes field wrapper conservatively, then use the rest for
    // the body itself.
    //
    // Encoded RpcPacket layout relevant to `body`:
    //
    //   +------------------------------- max_encoded_len -------------------------------+
    //   | fixed RpcPacket fields | body tag (1B) | body len varint (worst-case) | body |
    //   +--------------------------------------------------------------------------- --+
    //   ^                         ^
    //   |                         `- reserve by using the varint width of `budget`
    //   `- base_encoded_len_without_body
    //
    // This is intentionally conservative. A few bytes may be left unused, but
    // every piece stays within the UDP payload budget without iterative sizing.
    let reserved_for_body_header = 1 + length_delimiter_len(budget);
    remaining
        .min(budget.saturating_sub(reserved_for_body_header))
        .max(1)
}

// Pre-split the raw RPC content using conservative worst-case protobuf sizing.
// We compute separate base sizes because only the first piece carries
// `compression_info`.
//
// Split flow:
//
//   raw RPC content
//   +--------------------------------------------------------------+
//   |                         args.content                          |
//   +--------------------------------------------------------------+
//        | first piece uses first_piece_base_len
//        | later pieces use other_piece_base_len
//        v
//   +-----------+-----------+-----------+----- ...
//   | offset,len| offset,len| offset,len|
//   +-----------+-----------+-----------+----- ...
//
// The result is only a slicing plan. Actual RpcPacket objects are built later
// with the real `total_pieces`.
fn split_rpc_content_for_udp_budget(args: &BuildRpcPacketArgs<'_>) -> Vec<(usize, usize)> {
    if args.content.is_empty() {
        return vec![(0, 0)];
    }

    let max_encoded_len = max_rpc_packet_encoded_len_for_udp().max(1);
    // Use the worst-case varint width for piece counters so the budget remains
    // valid without iterating on `total_pieces`/`piece_idx`.
    let first_piece_base_len = build_rpc_piece(args, u32::MAX, 0, &[]).encoded_len();
    let other_piece_base_len = build_rpc_piece(args, u32::MAX, u32::MAX, &[]).encoded_len();

    let mut pieces = Vec::new();
    let mut offset = 0usize;
    while offset < args.content.len() {
        // The first piece has a different metadata shape because it carries
        // `compression_info`.
        let base_len = if pieces.is_empty() {
            first_piece_base_len
        } else {
            other_piece_base_len
        };
        let piece_len =
            pick_piece_len_for_budget(base_len, args.content.len() - offset, max_encoded_len);
        pieces.push((offset, piece_len));
        offset += piece_len;
    }

    pieces
}

// Build the final transport packets after the payload has been split. We do the
// actual `total_pieces` assignment only here so the wire packet stays accurate,
// while the earlier sizing step remains simple and conservatively safe.
pub fn build_rpc_packet(args: BuildRpcPacketArgs<'_>) -> Vec<ZCPacket> {
    let mut ret = Vec::new();
    let pieces = split_rpc_content_for_udp_budget(&args);
    let total_pieces = pieces.len() as u32;
    for (piece_idx, (offset, len)) in pieces.into_iter().enumerate() {
        let cur_packet = build_rpc_piece(
            &args,
            total_pieces,
            piece_idx as u32,
            &args.content[offset..offset + len],
        );

        let packet_type = if args.is_req {
            PacketType::RpcReq
        } else {
            PacketType::RpcResp
        };

        let mut buf = Vec::new();
        cur_packet.encode(&mut buf).unwrap();
        let mut zc_packet = ZCPacket::new_with_payload(&buf);
        zc_packet.fill_peer_manager_hdr(args.from_peer, args.to_peer, packet_type as u8);
        ret.push(zc_packet);
    }

    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment(
        descriptor: RpcDescriptor,
        total_pieces: u32,
        piece_idx: u32,
        body: &[u8],
    ) -> RpcPacket {
        RpcPacket {
            from_peer: 1,
            to_peer: 2,
            transaction_id: 3,
            descriptor: Some(descriptor),
            is_request: true,
            total_pieces,
            piece_idx,
            body: body.to_vec(),
            compression_info: (piece_idx == 0).then_some(RpcCompressionInfo {
                algo: CompressionAlgoPb::None as i32,
                accepted_algo: CompressionAlgoPb::None as i32,
            }),
            ..Default::default()
        }
    }

    fn test_descriptor(service_name: &str) -> RpcDescriptor {
        RpcDescriptor {
            domain_name: "test".to_string(),
            proto_name: "TestRpc".to_string(),
            service_name: service_name.to_string(),
            method_index: 1,
        }
    }

    fn build_test_args<'a>(
        content: &'a [u8],
        compression_algo: CompressionAlgoPb,
    ) -> BuildRpcPacketArgs<'a> {
        BuildRpcPacketArgs {
            from_peer: 11,
            to_peer: 22,
            rpc_desc: RpcDescriptor {
                domain_name: "very-long-domain-name-for-rpc-packet-budget-check".repeat(2),
                proto_name: "extremely.verbose.proto.name.for.rpc.packet.tests".repeat(2),
                service_name: "LargeMetadataServiceForRpcPacketBudget".repeat(2),
                method_index: 7,
            },
            transaction_id: 33,
            is_req: true,
            content,
            trace_id: 44,
            compression_info: RpcCompressionInfo {
                algo: compression_algo.into(),
                accepted_algo: CompressionAlgoPb::Zstd.into(),
            },
        }
    }

    fn udp_packet_size_after_tail(packet: &ZCPacket) -> usize {
        ZCPacketType::UDP.get_packet_offsets().payload_offset
            + packet.payload_len()
            + TAIL_RESERVED_SIZE
    }

    #[test]
    fn build_rpc_packet_respects_udp_budget_with_large_metadata() {
        let content = vec![0x5a; 4096];
        let packets = build_rpc_packet(build_test_args(&content, CompressionAlgoPb::None));

        assert!(packets.len() > 1);
        for packet in packets {
            assert!(
                udp_packet_size_after_tail(&packet) <= RPC_PACKET_UDP_PAYLOAD_BUDGET,
                "packet size {} exceeded budget {}",
                udp_packet_size_after_tail(&packet),
                RPC_PACKET_UDP_PAYLOAD_BUDGET
            );
        }
    }

    #[test]
    fn build_rpc_packet_keeps_descriptor_on_every_piece() {
        let content = vec![0x5a; 4096];
        let args = build_test_args(&content, CompressionAlgoPb::Zstd);
        let expected = args.rpc_desc.clone();
        let packets = build_rpc_packet(args);

        assert!(packets.len() > 1);
        for packet in packets {
            let rpc_packet = RpcPacket::decode(packet.payload()).unwrap();
            assert_eq!(rpc_packet.descriptor, Some(expected.clone()));
        }
    }

    #[test]
    fn build_rpc_packet_respects_udp_budget_for_empty_payload() {
        let packets = build_rpc_packet(build_test_args(&[], CompressionAlgoPb::Zstd));

        assert_eq!(1, packets.len());
        assert!(udp_packet_size_after_tail(&packets[0]) <= RPC_PACKET_UDP_PAYLOAD_BUDGET);
    }

    #[test]
    fn merger_rejects_mixed_fragment_descriptors() {
        let mut merger = PacketMerger::new();
        assert!(
            merger
                .feed(fragment(test_descriptor("A"), 2, 0, b"a"))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            merger.feed(fragment(test_descriptor("B"), 2, 1, b"b")),
            Err(Error::MalformatRpcPacket(_))
        ));
    }

    #[test]
    fn merger_rejects_total_piece_count_mutation() {
        let mut merger = PacketMerger::new();
        merger
            .feed(fragment(test_descriptor("A"), 2, 0, b"a"))
            .unwrap();
        assert!(matches!(
            merger.feed(fragment(test_descriptor("A"), 3, 1, b"b")),
            Err(Error::MalformatRpcPacket(_))
        ));
    }

    #[test]
    fn merger_rejects_conflicting_duplicate_body() {
        let mut merger = PacketMerger::new();
        merger
            .feed(fragment(test_descriptor("A"), 2, 0, b"a"))
            .unwrap();
        assert!(matches!(
            merger.feed(fragment(test_descriptor("A"), 2, 0, b"different")),
            Err(Error::MalformatRpcPacket(_))
        ));
    }

    #[test]
    fn merger_rejects_body_size_limit() {
        let mut merger = PacketMerger::new();
        let body = vec![0u8; MAX_RPC_BODY_BYTES + 1];
        assert!(matches!(
            merger.feed(fragment(test_descriptor("A"), 1, 0, &body)),
            Err(Error::MalformatRpcPacket(_))
        ));
    }

    #[test]
    fn merger_keeps_sparse_storage_for_a_large_piece_count() {
        let mut merger = PacketMerger::new();
        let packet = fragment(test_descriptor("A"), MAX_RPC_PIECES, 0, b"a");
        let encoded = packet.encoded_len();
        merger.feed(packet).unwrap();
        assert_eq!(merger.pieces.len(), 1);
        assert_eq!(merger.retained_body_bytes(), 1);
        assert_eq!(
            merger.retained_bytes(),
            encoded + RPC_MERGER_MAP_ENTRY_OVERHEAD + RPC_MERGER_ENVELOPE_OVERHEAD
        );
    }

    #[test]
    fn merger_does_not_clone_a_first_fragment_body() {
        let mut merger = PacketMerger::new();
        let body = vec![0u8; 4096];
        let packet = fragment(test_descriptor("A"), 2, 1, &body);
        let encoded = packet.encoded_len();
        merger.feed(packet).unwrap();
        assert_eq!(
            merger.retained_bytes(),
            encoded + RPC_MERGER_MAP_ENTRY_OVERHEAD + RPC_MERGER_ENVELOPE_OVERHEAD
        );
        assert!(merger.retained_bytes() < encoded * 2);
    }

    #[test]
    fn merger_reservation_matches_first_fragment_retained_bytes() {
        let packet = fragment(test_descriptor("A"), 2, 1, b"a");
        let reservation = PacketMerger::reservation_bytes(&packet, true).unwrap();
        let mut merger = PacketMerger::new();
        merger.feed(packet).unwrap();
        assert_eq!(reservation, merger.retained_bytes());
    }

    #[cfg(feature = "zstd")]
    #[tokio::test]
    async fn decompression_rejects_expansion_bomb() {
        let body = vec![0u8; MAX_RPC_BODY_BYTES + 1];
        let compressed = zstd::bulk::compress(&body, 1).unwrap();
        assert!(matches!(
            decompress_packet(CompressionAlgoPb::Zstd, &compressed).await,
            Err(Error::MalformatRpcPacket(_))
        ));
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn logical_body_size_uses_bounded_zstd_frame_size() {
        let logical = vec![0x5a; 1024];
        let compressed = zstd::bulk::compress(&logical, 1).unwrap();
        let packet = RpcPacket {
            body: compressed,
            compression_info: Some(RpcCompressionInfo {
                algo: CompressionAlgoPb::Zstd.into(),
                accepted_algo: CompressionAlgoPb::Zstd.into(),
            }),
            ..Default::default()
        };
        assert_eq!(logical_body_size(&packet).unwrap(), logical.len());
        assert!(packet.body.len() < logical.len());
    }
}
