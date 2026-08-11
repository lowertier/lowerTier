use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use anyhow::{Context as _, ensure};
use bytes::{Bytes, BytesMut};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

use crate::tunnel::packet_def::{
    COMPRESSOR_TAIL_SIZE, PEER_MANAGER_HEADER_SIZE, PacketType, StandardAeadTail, ZCPacket,
    ZCPacketType,
};

const SOURCE_KIND: u8 = 1;
const PARITY_KIND: u8 = 2;
const SOURCE_HEADER_LEN: usize = 10;
const PARITY_HEADER_LEN: usize = 14;
const SOURCE_TARGET: usize = 16;
const MAX_SOURCE_BYTES: usize = u16::MAX as usize;
const MAX_BLOCKS: usize = 4096;
const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_COMPLETED_BLOCKS: usize = 65_536;
const BLOCK_TTL: Duration = Duration::from_secs(5);
const COMPLETED_TTL: Duration = Duration::from_secs(10);
pub(crate) const FEC_FLUSH_DELAY: Duration = Duration::from_millis(40);

#[derive(Debug)]
pub(crate) struct CompletedAlternateFecBlock {
    pub block_id: u64,
    pub source_count: usize,
    pub parity: Vec<Bytes>,
}

#[derive(Debug)]
pub(crate) struct AlternateFecPushOutput {
    pub source: Bytes,
    pub completed: Option<CompletedAlternateFecBlock>,
}

pub(crate) struct AlternateFecEncoder {
    parity_count: usize,
    flush_delay: Duration,
    block_id: u64,
    started_at: Option<Instant>,
    sources: Vec<Bytes>,
}

impl AlternateFecEncoder {
    pub fn new(parity_count: usize, flush_delay: Duration) -> anyhow::Result<Self> {
        ensure!(
            (1..=3).contains(&parity_count),
            "invalid alternate FEC parity count"
        );
        ensure!(!flush_delay.is_zero(), "alternate FEC flush delay is zero");
        Ok(Self {
            parity_count,
            flush_delay,
            block_id: 1,
            started_at: None,
            sources: Vec::with_capacity(SOURCE_TARGET),
        })
    }

    pub fn push(&mut self, source: Bytes, now: Instant) -> anyhow::Result<AlternateFecPushOutput> {
        ensure!(!source.is_empty(), "alternate FEC source is empty");
        if self.sources.is_empty() {
            self.started_at = Some(now);
        }
        let source_index = self.sources.len();
        let source_record = encode_source(self.block_id, source_index, source.clone())?;
        self.sources.push(source);
        let completed = (self.sources.len() == SOURCE_TARGET)
            .then(|| self.flush())
            .transpose()?;
        Ok(AlternateFecPushOutput {
            source: source_record,
            completed,
        })
    }

    pub fn flush_due(&mut self, now: Instant) -> anyhow::Result<CompletedAlternateFecBlock> {
        ensure!(!self.sources.is_empty(), "alternate FEC block is empty");
        ensure!(
            self.started_at
                .is_some_and(|started| now.saturating_duration_since(started) >= self.flush_delay),
            "alternate FEC block is not due"
        );
        self.flush()
    }

    pub fn take_due(&mut self, now: Instant) -> anyhow::Result<Option<CompletedAlternateFecBlock>> {
        if self.sources.is_empty()
            || self
                .started_at
                .is_none_or(|started| now.saturating_duration_since(started) < self.flush_delay)
        {
            return Ok(None);
        }
        self.flush().map(Some)
    }

    pub fn next_flush_at(&self) -> Option<Instant> {
        self.started_at.map(|started| started + self.flush_delay)
    }

    fn flush(&mut self) -> anyhow::Result<CompletedAlternateFecBlock> {
        let source_count = self.sources.len();
        let parity = encode_block(&self.sources, self.parity_count)?
            .into_iter()
            .enumerate()
            .map(|(index, shard)| {
                encode_parity(self.block_id, source_count, self.parity_count, index, shard)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let block = CompletedAlternateFecBlock {
            block_id: self.block_id,
            source_count,
            parity,
        };
        self.block_id = self.block_id.wrapping_add(1).max(1);
        self.sources.clear();
        self.started_at = None;
        Ok(block)
    }
}

enum AlternateFecRecord {
    Source {
        block_id: u64,
        source_index: usize,
        datagram: Bytes,
    },
    Parity {
        block_id: u64,
        source_count: usize,
        parity_count: usize,
        parity_index: usize,
        shard: Bytes,
    },
}

fn encode_source(block_id: u64, source_index: usize, source: Bytes) -> anyhow::Result<Bytes> {
    ensure!(block_id != 0, "alternate FEC block ID is zero");
    ensure!(
        source_index < SOURCE_TARGET,
        "alternate FEC source index is invalid"
    );
    let mut record = Vec::with_capacity(SOURCE_HEADER_LEN + source.len());
    record.push(SOURCE_KIND);
    record.extend_from_slice(&block_id.to_be_bytes());
    record.push(source_index as u8);
    record.extend_from_slice(&source);
    Ok(Bytes::from(record))
}

fn encode_parity(
    block_id: u64,
    source_count: usize,
    parity_count: usize,
    parity_index: usize,
    shard: Bytes,
) -> anyhow::Result<Bytes> {
    ensure!(block_id != 0, "alternate FEC block ID is zero");
    ensure!(
        (1..=SOURCE_TARGET).contains(&source_count),
        "invalid source count"
    );
    ensure!((1..=3).contains(&parity_count), "invalid parity count");
    ensure!(parity_index < parity_count, "invalid parity index");
    ensure!(
        shard.len() <= u16::MAX as usize,
        "alternate FEC parity is too large"
    );
    let mut record = Vec::with_capacity(PARITY_HEADER_LEN + shard.len());
    record.push(PARITY_KIND);
    record.extend_from_slice(&block_id.to_be_bytes());
    record.push(source_count as u8);
    record.push(parity_count as u8);
    record.push(parity_index as u8);
    record.extend_from_slice(&(shard.len() as u16).to_be_bytes());
    record.extend_from_slice(&shard);
    Ok(Bytes::from(record))
}

fn decode_record(record: Bytes) -> anyhow::Result<AlternateFecRecord> {
    ensure!(
        record.len() >= SOURCE_HEADER_LEN,
        "alternate FEC record is too short"
    );
    let block_id = u64::from_be_bytes(record[1..9].try_into().unwrap());
    ensure!(block_id != 0, "alternate FEC block ID is zero");
    match record[0] {
        SOURCE_KIND => {
            let source_index = usize::from(record[9]);
            ensure!(
                source_index < SOURCE_TARGET,
                "invalid alternate FEC source index"
            );
            ensure!(
                record.len() > SOURCE_HEADER_LEN,
                "alternate FEC source is empty"
            );
            Ok(AlternateFecRecord::Source {
                block_id,
                source_index,
                datagram: record.slice(SOURCE_HEADER_LEN..),
            })
        }
        PARITY_KIND => {
            ensure!(
                record.len() >= PARITY_HEADER_LEN,
                "alternate FEC parity is too short"
            );
            let source_count = usize::from(record[9]);
            let parity_count = usize::from(record[10]);
            let parity_index = usize::from(record[11]);
            let shard_len = usize::from(u16::from_be_bytes(record[12..14].try_into().unwrap()));
            ensure!(
                (1..=SOURCE_TARGET).contains(&source_count),
                "invalid source count"
            );
            ensure!((1..=3).contains(&parity_count), "invalid parity count");
            ensure!(parity_index < parity_count, "invalid parity index");
            ensure!(
                record.len() == PARITY_HEADER_LEN + shard_len,
                "alternate FEC parity length mismatch"
            );
            Ok(AlternateFecRecord::Parity {
                block_id,
                source_count,
                parity_count,
                parity_index,
                shard: record.slice(PARITY_HEADER_LEN..),
            })
        }
        _ => anyhow::bail!("unknown alternate FEC record kind"),
    }
}

fn shard_bytes(sources: &[Bytes]) -> anyhow::Result<usize> {
    let longest = sources.iter().map(Bytes::len).max().unwrap_or(0);
    ensure!(!sources.is_empty(), "FEC block has no source symbols");
    ensure!(
        longest <= MAX_SOURCE_BYTES,
        "FEC source symbol is too large"
    );
    Ok((longest + 2).next_multiple_of(2))
}

fn padded_source(source: &Bytes, shard_bytes: usize) -> anyhow::Result<Vec<u8>> {
    ensure!(
        source.len() <= MAX_SOURCE_BYTES && source.len() + 2 <= shard_bytes,
        "FEC source symbol does not fit the announced shard size"
    );
    let mut shard = vec![0_u8; shard_bytes];
    shard[..2].copy_from_slice(&(source.len() as u16).to_be_bytes());
    shard[2..2 + source.len()].copy_from_slice(source);
    Ok(shard)
}

fn encode_block(sources: &[Bytes], parity_count: usize) -> anyhow::Result<Vec<Bytes>> {
    ensure!(
        (1..=SOURCE_TARGET).contains(&sources.len()),
        "invalid FEC source count"
    );
    ensure!((1..=3).contains(&parity_count), "invalid FEC parity count");
    let shard_bytes = shard_bytes(sources)?;
    let mut encoder = ReedSolomonEncoder::new(sources.len(), parity_count, shard_bytes)
        .context("create SIMD Reed-Solomon encoder")?;
    for source in sources {
        encoder
            .add_original_shard(padded_source(source, shard_bytes)?)
            .context("add systematic FEC source shard")?;
    }
    Ok(encoder
        .encode()
        .context("encode SIMD Reed-Solomon parity")?
        .recovery_iter()
        .map(Bytes::copy_from_slice)
        .collect())
}

fn recover_block_indexed(
    sources: &[Option<Bytes>],
    parity: &[(usize, Bytes)],
    parity_count: usize,
) -> anyhow::Result<Vec<(usize, Bytes)>> {
    ensure!(
        (1..=SOURCE_TARGET).contains(&sources.len()),
        "invalid FEC source count"
    );
    ensure!((1..=3).contains(&parity_count), "invalid FEC parity count");
    let shard_bytes = parity
        .first()
        .map(|(_, shard)| shard.len())
        .context("FEC recovery has no parity symbols")?;
    ensure!(
        shard_bytes >= 2 && shard_bytes.is_multiple_of(2),
        "invalid FEC shard size"
    );
    ensure!(
        parity.iter().all(|(_, shard)| shard.len() == shard_bytes),
        "FEC parity shard sizes differ"
    );

    let mut decoder = ReedSolomonDecoder::new(sources.len(), parity_count, shard_bytes)
        .context("create SIMD Reed-Solomon decoder")?;
    for (index, source) in sources.iter().enumerate() {
        if let Some(source) = source {
            decoder
                .add_original_shard(index, padded_source(source, shard_bytes)?)
                .context("add received systematic FEC source")?;
        }
    }
    for (index, shard) in parity {
        ensure!(*index < parity_count, "FEC parity index is out of range");
        decoder
            .add_recovery_shard(*index, shard)
            .context("add received FEC parity")?;
    }

    let result = decoder.decode().context("recover missing FEC sources")?;
    let mut recovered = Vec::new();
    for (index, shard) in result.restored_original_iter() {
        let encoded_len = usize::from(u16::from_be_bytes([shard[0], shard[1]]));
        ensure!(
            encoded_len > 0 && encoded_len + 2 <= shard.len(),
            "recovered FEC source has an invalid encoded length"
        );
        recovered.push((index, Bytes::copy_from_slice(&shard[2..2 + encoded_len])));
    }
    Ok(recovered)
}

struct ReceiveBlock {
    sources: Vec<Option<Bytes>>,
    parity: Vec<Option<Bytes>>,
    source_count: Option<usize>,
    parity_count: Option<usize>,
    retained_bytes: usize,
    created_at: Instant,
}

impl ReceiveBlock {
    fn new(now: Instant) -> Self {
        Self {
            sources: vec![None; SOURCE_TARGET],
            parity: vec![None; 3],
            source_count: None,
            parity_count: None,
            retained_bytes: 0,
            created_at: now,
        }
    }
}

#[derive(Default)]
pub(crate) struct AlternateFecDecodeOutput {
    pub datagrams: Vec<Bytes>,
    pub expired_blocks: usize,
}

#[derive(Default)]
pub(crate) struct AlternateFecDecoder {
    blocks: HashMap<u64, ReceiveBlock>,
    retained_bytes: usize,
    completed: HashSet<u64>,
    completed_order: VecDeque<(u64, Instant)>,
}

impl AlternateFecDecoder {
    pub fn ingest(
        &mut self,
        record: Bytes,
        now: Instant,
    ) -> anyhow::Result<AlternateFecDecodeOutput> {
        let expired_blocks = self.expire(now);
        let mut datagrams = Vec::new();
        match decode_record(record)? {
            AlternateFecRecord::Source {
                block_id,
                source_index,
                datagram,
            } => {
                if self.completed.contains(&block_id) {
                    return Ok(AlternateFecDecodeOutput {
                        expired_blocks,
                        ..Default::default()
                    });
                }
                ensure!(
                    self.retained_bytes.saturating_add(datagram.len()) <= MAX_RETAINED_BYTES,
                    "alternate FEC byte limit reached"
                );
                let added = {
                    let block = self.ensure_block(block_id, now)?;
                    if let Some(source_count) = block.source_count {
                        ensure!(
                            source_index < source_count,
                            "source exceeds announced count"
                        );
                    }
                    match &block.sources[source_index] {
                        Some(previous) => {
                            ensure!(previous == &datagram, "alternate FEC source changed");
                            0
                        }
                        None => {
                            let len = datagram.len();
                            block.sources[source_index] = Some(datagram.clone());
                            block.retained_bytes += len;
                            datagrams.push(datagram);
                            len
                        }
                    }
                };
                self.retained_bytes += added;
                datagrams.extend(self.try_recover(block_id, now)?);
            }
            AlternateFecRecord::Parity {
                block_id,
                source_count,
                parity_count,
                parity_index,
                shard,
            } => {
                if self.completed.contains(&block_id) {
                    return Ok(AlternateFecDecodeOutput {
                        expired_blocks,
                        ..Default::default()
                    });
                }
                ensure!(
                    self.retained_bytes.saturating_add(shard.len()) <= MAX_RETAINED_BYTES,
                    "alternate FEC byte limit reached"
                );
                let added = {
                    let block = self.ensure_block(block_id, now)?;
                    if let Some(previous) = block.source_count {
                        ensure!(
                            previous == source_count,
                            "alternate FEC source count changed"
                        );
                    }
                    if let Some(previous) = block.parity_count {
                        ensure!(
                            previous == parity_count,
                            "alternate FEC parity count changed"
                        );
                    }
                    ensure!(
                        block.sources[source_count..].iter().all(Option::is_none),
                        "source exceeds announced count"
                    );
                    block.source_count = Some(source_count);
                    block.parity_count = Some(parity_count);
                    match &block.parity[parity_index] {
                        Some(previous) => {
                            ensure!(previous == &shard, "alternate FEC parity changed");
                            0
                        }
                        None => {
                            let len = shard.len();
                            block.parity[parity_index] = Some(shard);
                            block.retained_bytes += len;
                            len
                        }
                    }
                };
                self.retained_bytes += added;
                datagrams.extend(self.try_recover(block_id, now)?);
            }
        }
        Ok(AlternateFecDecodeOutput {
            datagrams,
            expired_blocks,
        })
    }

    fn ensure_block(&mut self, block_id: u64, now: Instant) -> anyhow::Result<&mut ReceiveBlock> {
        if !self.blocks.contains_key(&block_id) {
            ensure!(
                self.blocks.len() < MAX_BLOCKS,
                "alternate FEC block limit reached"
            );
            self.blocks.insert(block_id, ReceiveBlock::new(now));
        }
        Ok(self.blocks.get_mut(&block_id).unwrap())
    }

    fn try_recover(&mut self, block_id: u64, now: Instant) -> anyhow::Result<Vec<Bytes>> {
        let block = self
            .blocks
            .get(&block_id)
            .context("alternate FEC block disappeared")?;
        let (Some(source_count), Some(parity_count)) = (block.source_count, block.parity_count)
        else {
            return Ok(Vec::new());
        };
        let sources = block.sources[..source_count].to_vec();
        let missing = sources.iter().filter(|source| source.is_none()).count();
        if missing == 0 {
            self.complete(block_id, now);
            return Ok(Vec::new());
        }
        let parity = block.parity[..parity_count]
            .iter()
            .enumerate()
            .filter_map(|(index, shard)| shard.clone().map(|shard| (index, shard)))
            .collect::<Vec<_>>();
        if parity.len() < missing {
            return Ok(Vec::new());
        }
        let recovered = recover_block_indexed(&sources, &parity, parity_count)?
            .into_iter()
            .map(|(_, datagram)| datagram)
            .collect();
        self.complete(block_id, now);
        Ok(recovered)
    }

    fn complete(&mut self, block_id: u64, now: Instant) {
        if let Some(block) = self.blocks.remove(&block_id) {
            self.retained_bytes = self.retained_bytes.saturating_sub(block.retained_bytes);
        }
        if self.completed.insert(block_id) {
            self.completed_order.push_back((block_id, now));
        }
        while self.completed.len() > MAX_COMPLETED_BLOCKS {
            let (oldest, _) = self.completed_order.pop_front().unwrap();
            self.completed.remove(&oldest);
        }
    }

    fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0;
        let mut bytes = 0;
        self.blocks.retain(|_, block| {
            let keep = now.saturating_duration_since(block.created_at) <= BLOCK_TTL;
            if !keep {
                expired += 1;
                bytes += block.retained_bytes;
            }
            keep
        });
        self.retained_bytes = self.retained_bytes.saturating_sub(bytes);
        while self
            .completed_order
            .front()
            .is_some_and(|(_, at)| now.saturating_duration_since(*at) > COMPLETED_TTL)
        {
            let (block_id, _) = self.completed_order.pop_front().unwrap();
            self.completed.remove(&block_id);
        }
        expired
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AlternateFecSourceMetadata {
    from_peer_id: u32,
    to_peer_id: u32,
    flow_shard: Option<u16>,
    critical: bool,
}

pub(crate) fn source_metadata(packet: &ZCPacket) -> anyhow::Result<AlternateFecSourceMetadata> {
    let header = packet
        .peer_manager_header()
        .context("alternate FEC source has no peer header")?;
    Ok(AlternateFecSourceMetadata {
        from_peer_id: header.from_peer_id.get(),
        to_peer_id: header.to_peer_id.get(),
        flow_shard: header.flow_shard(),
        critical: header.is_critical_l2_control(),
    })
}

pub(crate) fn wrap_source_packet(
    metadata: AlternateFecSourceMetadata,
    source_record: Bytes,
) -> ZCPacket {
    let mut wrapped = ZCPacket::new_with_payload(&source_record);
    wrapped.fill_peer_manager_hdr(
        metadata.from_peer_id,
        metadata.to_peer_id,
        PacketType::AlternateFecSource as u8,
    );
    let wrapped_header = wrapped.mut_peer_manager_header().unwrap();
    if let Some(flow_shard) = metadata.flow_shard {
        wrapped_header.set_flow_shard(flow_shard);
    }
    wrapped_header.set_critical_l2_control(metadata.critical);
    wrapped
}

pub(crate) fn parity_packets(
    from_peer_id: u32,
    immediate_peer_id: u32,
    block: CompletedAlternateFecBlock,
) -> Vec<ZCPacket> {
    block
        .parity
        .into_iter()
        .map(|record| {
            let mut packet = ZCPacket::new_with_payload(&record);
            packet.fill_peer_manager_hdr(
                from_peer_id,
                immediate_peer_id,
                PacketType::AlternateFecParity as u8,
            );
            packet
        })
        .collect()
}

pub(crate) fn decode_alternate_fec_packet(
    packet: ZCPacket,
    decoder: &mut AlternateFecDecoder,
    now: Instant,
) -> anyhow::Result<Vec<ZCPacket>> {
    let outer_header = packet
        .peer_manager_header()
        .context("alternate FEC packet has no peer header")?;
    let packet_type = outer_header.packet_type;
    let authenticated_from_peer_id = outer_header.from_peer_id.get();
    let authenticated_to_peer_id = outer_header.to_peer_id.get();
    ensure!(
        packet_type == PacketType::AlternateFecSource as u8
            || packet_type == PacketType::AlternateFecParity as u8,
        "packet is not an alternate FEC record"
    );
    decoder
        .ingest(packet.payload_bytes().freeze(), now)?
        .datagrams
        .into_iter()
        .map(|datagram| {
            ensure!(
                datagram.len() >= PEER_MANAGER_HEADER_SIZE,
                "recovered alternate FEC packet is too short"
            );
            let buffer = datagram
                .try_into_mut()
                .unwrap_or_else(|shared| BytesMut::from(shared.as_ref()));
            let packet = ZCPacket::new_from_buf(buffer, ZCPacketType::DummyTunnel);
            let header = packet
                .peer_manager_header()
                .context("recovered alternate FEC packet has no peer header")?;
            ensure!(
                header.from_peer_id.get() == authenticated_from_peer_id
                    && header.to_peer_id.get() == authenticated_to_peer_id,
                "recovered alternate FEC packet does not match authenticated peer IDs"
            );
            ensure!(
                encoded_payload_len_matches_header(header, packet.payload_len()),
                "recovered alternate FEC packet length mismatch"
            );
            Ok(packet)
        })
        .collect()
}

fn encoded_payload_len_matches_header(
    header: &crate::tunnel::packet_def::PeerManagerHeader,
    payload_len: usize,
) -> bool {
    let original_len = header.len.get() as usize;
    match (header.is_encrypted(), header.is_compressed()) {
        (false, false) => payload_len == original_len,
        (true, false) => payload_len == original_len.saturating_add(StandardAeadTail::SIZE),
        (false, true) => payload_len >= COMPRESSOR_TAIL_SIZE && payload_len <= original_len,
        (true, true) => {
            payload_len >= StandardAeadTail::SIZE.saturating_add(COMPRESSOR_TAIL_SIZE)
                && payload_len <= original_len.saturating_add(StandardAeadTail::SIZE)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bytes::Bytes;

    use super::{
        AlternateFecDecoder, AlternateFecEncoder, SOURCE_HEADER_LEN, SOURCE_KIND,
        decode_alternate_fec_packet, parity_packets, source_metadata, wrap_source_packet,
    };
    use crate::tunnel::packet_def::{PacketType, StandardAeadTail, ZCPacket};

    fn sources(count: usize) -> Vec<Bytes> {
        (0..count)
            .map(|index| Bytes::from(vec![index as u8; 96 + index * 11]))
            .collect()
    }

    #[test]
    fn alternate_path_16_plus_2_recovers_two_missing_sources() {
        let now = Instant::now();
        let expected = sources(16);
        let mut encoder = AlternateFecEncoder::new(2, Duration::from_millis(40)).unwrap();
        let mut source_records = Vec::new();
        let mut parity = None;
        for source in &expected {
            let output = encoder.push(source.clone(), now).unwrap();
            source_records.push(output.source);
            parity = output.completed.or(parity);
        }

        let mut decoder = AlternateFecDecoder::default();
        let mut delivered = Vec::new();
        for (index, record) in source_records.into_iter().enumerate() {
            if index != 3 && index != 11 {
                delivered.extend(decoder.ingest(record, now).unwrap().datagrams);
            }
        }
        for record in parity.unwrap().parity {
            delivered.extend(decoder.ingest(record, now).unwrap().datagrams);
        }

        delivered.sort();
        let mut expected = expected;
        expected.sort();
        assert_eq!(delivered, expected);
    }

    #[test]
    fn completed_block_suppresses_a_late_source_duplicate() {
        let now = Instant::now();
        let expected = sources(16);
        let mut encoder = AlternateFecEncoder::new(2, Duration::from_millis(40)).unwrap();
        let mut source_records = Vec::new();
        let mut parity = None;
        for source in &expected {
            let output = encoder.push(source.clone(), now).unwrap();
            source_records.push(output.source);
            parity = output.completed.or(parity);
        }

        let late = source_records[7].clone();
        let mut decoder = AlternateFecDecoder::default();
        for (index, record) in source_records.into_iter().enumerate() {
            if index != 7 {
                decoder.ingest(record, now).unwrap();
            }
        }
        for record in parity.unwrap().parity {
            decoder.ingest(record, now).unwrap();
        }

        assert!(decoder.ingest(late, now).unwrap().datagrams.is_empty());
    }

    #[test]
    fn partial_block_flush_preserves_source_count() {
        let now = Instant::now();
        let expected = sources(9);
        let mut encoder = AlternateFecEncoder::new(2, Duration::from_millis(40)).unwrap();
        let mut source_records = Vec::new();
        for source in &expected {
            source_records.push(encoder.push(source.clone(), now).unwrap().source);
        }
        let parity = encoder.flush_due(now + Duration::from_millis(40)).unwrap();
        assert_eq!(parity.source_count, 9);

        let mut decoder = AlternateFecDecoder::default();
        let mut delivered = Vec::new();
        for (index, record) in source_records.into_iter().enumerate() {
            if index != 4 {
                delivered.extend(decoder.ingest(record, now).unwrap().datagrams);
            }
        }
        for record in parity.parity {
            delivered.extend(decoder.ingest(record, now).unwrap().datagrams);
        }
        delivered.sort();
        let mut expected = expected;
        expected.sort();
        assert_eq!(delivered, expected);
    }

    #[test]
    fn encoder_exposes_a_deadline_only_for_pending_data() {
        let now = Instant::now();
        let delay = Duration::from_millis(40);
        let mut encoder = AlternateFecEncoder::new(2, delay).unwrap();

        assert_eq!(encoder.next_flush_at(), None);
        let first = encoder.push(Bytes::from_static(b"first"), now).unwrap();
        assert_eq!(first.source.len(), SOURCE_HEADER_LEN + 5);
        assert_eq!(first.source[0], SOURCE_KIND);
        assert_eq!(encoder.next_flush_at(), Some(now + delay));

        for _ in 1..16 {
            encoder.push(Bytes::from_static(b"next"), now).unwrap();
        }
        assert_eq!(encoder.next_flush_at(), None);
    }

    #[test]
    fn packet_wrapper_round_trip_preserves_header_payload_and_markers() {
        let now = Instant::now();
        let mut original = ZCPacket::new_with_payload(b"ethernet-frame");
        original.fill_peer_manager_hdr(11, 22, PacketType::Ethernet as u8);
        original
            .mut_peer_manager_header()
            .unwrap()
            .set_flow_shard(17);
        original
            .mut_peer_manager_header()
            .unwrap()
            .set_critical_l2_control(true);
        let expected = original.tunnel_payload().to_vec();

        let mut encoder = AlternateFecEncoder::new(2, Duration::from_millis(40)).unwrap();
        let encoded = encoder
            .push(Bytes::copy_from_slice(original.tunnel_payload()), now)
            .unwrap();
        let wrapped = wrap_source_packet(source_metadata(&original).unwrap(), encoded.source);
        let wrapped_header = wrapped.peer_manager_header().unwrap();
        assert_eq!(
            wrapped_header.packet_type,
            PacketType::AlternateFecSource as u8
        );
        assert_eq!(wrapped_header.flow_shard(), Some(17));
        assert!(wrapped_header.is_critical_l2_control());

        let mut decoder = AlternateFecDecoder::default();
        let recovered = decode_alternate_fec_packet(wrapped, &mut decoder, now).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].tunnel_payload(), expected);
    }

    #[test]
    fn packet_wrapper_accepts_an_already_encrypted_inner_packet() {
        let now = Instant::now();
        let mut original = ZCPacket::new_with_payload(b"encrypted-ethernet-frame");
        original.fill_peer_manager_hdr(11, 22, PacketType::Ethernet as u8);
        original
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(true);
        original
            .mut_inner()
            .extend_from_slice(&[0; StandardAeadTail::SIZE]);
        let expected = original.tunnel_payload().to_vec();

        let mut encoder = AlternateFecEncoder::new(2, Duration::from_millis(40)).unwrap();
        let encoded = encoder
            .push(Bytes::copy_from_slice(original.tunnel_payload()), now)
            .unwrap();
        let wrapped = wrap_source_packet(source_metadata(&original).unwrap(), encoded.source);

        let recovered =
            decode_alternate_fec_packet(wrapped, &mut AlternateFecDecoder::default(), now).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].tunnel_payload(), expected);
    }

    #[test]
    fn parity_packets_are_addressed_to_the_authenticated_immediate_peer() {
        let now = Instant::now();
        let mut encoder = AlternateFecEncoder::new(2, Duration::from_millis(40)).unwrap();
        let mut completed = None;
        for source in sources(16) {
            completed = encoder.push(source, now).unwrap().completed.or(completed);
        }
        let packets = parity_packets(31, 47, completed.unwrap());
        assert_eq!(packets.len(), 2);
        for packet in packets {
            let header = packet.peer_manager_header().unwrap();
            assert_eq!(header.from_peer_id.get(), 31);
            assert_eq!(header.to_peer_id.get(), 47);
            assert_eq!(header.packet_type, PacketType::AlternateFecParity as u8);
        }
    }

    #[test]
    fn authenticated_wrapper_identity_must_match_the_recovered_inner_header() {
        let now = Instant::now();
        let mut original = ZCPacket::new_with_payload(b"ethernet-frame");
        original.fill_peer_manager_hdr(11, 22, PacketType::Ethernet as u8);
        let mut encoder = AlternateFecEncoder::new(2, Duration::from_millis(40)).unwrap();
        let source = encoder
            .push(Bytes::copy_from_slice(original.tunnel_payload()), now)
            .unwrap()
            .source;
        let mut wrapped = wrap_source_packet(source_metadata(&original).unwrap(), source);
        wrapped
            .mut_peer_manager_header()
            .unwrap()
            .from_peer_id
            .set(99);

        let error = decode_alternate_fec_packet(wrapped, &mut AlternateFecDecoder::default(), now)
            .unwrap_err();
        assert!(error.to_string().contains("authenticated peer IDs"));
    }
}
