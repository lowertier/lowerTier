use anyhow::{Context, ensure};
use bytes::Bytes;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use super::reliable_datagram::{
    DatagramMessage, FEC_PARITY_HEADER_LEN, decode_datagram, encode_fec_parity, encode_fec_source,
};

const MAX_SOURCE_BYTES: usize = u16::MAX as usize;
pub(super) const FEC_SOURCE_TARGET: usize = 16;
pub(crate) const FEC_FLUSH_DELAY: Duration = Duration::from_millis(40);
const MAX_COMPLETED_BLOCKS: usize = MAX_RECEIVE_BLOCKS * 16;

#[derive(Debug)]
pub(super) struct EncodedFecBlock {
    pub block_id: u64,
    pub source_count: usize,
    pub parity: Vec<Bytes>,
    pub source_bytes: usize,
    pub parity_bytes: usize,
}

#[derive(Debug)]
pub(super) struct FecPushOutput {
    pub source: Bytes,
    pub completed: Option<EncodedFecBlock>,
}

pub(super) struct FecEncoderState {
    parity_count: usize,
    flush_delay: Duration,
    block_id: u64,
    started_at: Option<Instant>,
    sources: Vec<Bytes>,
}

impl FecEncoderState {
    pub fn new(parity_count: usize, flush_delay: Duration) -> anyhow::Result<Self> {
        ensure!((1..=3).contains(&parity_count), "invalid FEC parity count");
        ensure!(!flush_delay.is_zero(), "FEC flush delay is zero");
        Ok(Self {
            parity_count,
            flush_delay,
            block_id: 1,
            started_at: None,
            sources: Vec::with_capacity(FEC_SOURCE_TARGET),
        })
    }

    pub fn max_source_datagram_size(max_datagram_size: usize) -> anyhow::Result<usize> {
        max_datagram_size
            .checked_sub(FEC_PARITY_HEADER_LEN + 2)
            .filter(|size| *size > 21)
            .context("QUIC DATAGRAM MTU is too small for ETD4 FEC")
    }

    pub fn push(&mut self, source: Bytes, now: Instant) -> anyhow::Result<FecPushOutput> {
        ensure!(!source.is_empty(), "FEC source is empty");
        ensure!(source.len() <= MAX_SOURCE_BYTES, "FEC source is too large");
        if self.sources.is_empty() {
            self.started_at = Some(now);
        }
        let source_index = self.sources.len() as u8;
        let encoded_source = encode_fec_source(self.block_id, source_index, source.clone())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        self.sources.push(source);
        let completed = (self.sources.len() == FEC_SOURCE_TARGET)
            .then(|| self.close_block())
            .transpose()?;
        Ok(FecPushOutput {
            source: encoded_source,
            completed,
        })
    }

    pub fn flush_due(&mut self, now: Instant) -> anyhow::Result<Option<EncodedFecBlock>> {
        let due = self.started_at.is_some_and(|started_at| {
            now.saturating_duration_since(started_at) >= self.flush_delay
        });
        if !due {
            return Ok(None);
        }
        self.close_block().map(Some)
    }

    pub fn abort_block(&mut self) {
        self.sources.clear();
        self.started_at = None;
        self.advance_block_id();
    }

    fn advance_block_id(&mut self) {
        self.block_id = self.block_id.wrapping_add(1).max(1);
    }

    fn close_block(&mut self) -> anyhow::Result<EncodedFecBlock> {
        ensure!(!self.sources.is_empty(), "cannot close an empty FEC block");
        let block_id = self.block_id;
        let sources = std::mem::take(&mut self.sources);
        self.sources = Vec::with_capacity(FEC_SOURCE_TARGET);
        self.started_at = None;
        self.advance_block_id();

        let source_count = sources.len();
        let source_bytes = sources.iter().map(Bytes::len).sum();
        let raw_parity = encode_block(&sources, self.parity_count)?;
        let mut parity = Vec::with_capacity(self.parity_count);
        for (parity_index, shard) in raw_parity.into_iter().enumerate() {
            parity.push(
                encode_fec_parity(
                    block_id,
                    source_count as u8,
                    self.parity_count as u8,
                    parity_index as u8,
                    shard,
                )
                .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            );
        }
        let parity_bytes = parity.iter().map(Bytes::len).sum();
        Ok(EncodedFecBlock {
            block_id,
            source_count,
            parity,
            source_bytes,
            parity_bytes,
        })
    }
}

const MAX_RECEIVE_BLOCKS: usize = 4_096;
const MAX_RECEIVE_BYTES: usize = 64 * 1024 * 1024;
const RECEIVE_BLOCK_TTL: Duration = Duration::from_secs(5);
const COMPLETED_BLOCK_TTL: Duration = Duration::from_secs(10);

struct ReceiveBlock {
    sources: Vec<Option<Bytes>>,
    parity: Vec<Option<Bytes>>,
    source_count: Option<usize>,
    parity_count: Option<usize>,
    shard_bytes: Option<usize>,
    retained_bytes: usize,
    created_at: Instant,
}

impl ReceiveBlock {
    fn new(now: Instant) -> Self {
        Self {
            sources: vec![None; FEC_SOURCE_TARGET],
            parity: vec![None; 3],
            source_count: None,
            parity_count: None,
            shard_bytes: None,
            retained_bytes: 0,
            created_at: now,
        }
    }
}

#[derive(Default, Debug)]
pub(super) struct FecDecodeOutput {
    pub datagrams: Vec<Bytes>,
    pub expired_blocks: usize,
}

#[derive(Default)]
pub(super) struct FecDecoderState {
    blocks: HashMap<u64, ReceiveBlock>,
    retained_bytes: usize,
    completed: HashSet<u64>,
    completed_order: VecDeque<(u64, Instant)>,
}

impl FecDecoderState {
    fn expire(&mut self, now: Instant) -> usize {
        let mut expired_blocks = 0;
        let mut expired_bytes = 0;
        self.blocks.retain(|_, block| {
            let keep = now.saturating_duration_since(block.created_at) <= RECEIVE_BLOCK_TTL;
            if !keep {
                expired_blocks += 1;
                expired_bytes += block.retained_bytes;
            }
            keep
        });
        self.retained_bytes = self.retained_bytes.saturating_sub(expired_bytes);
        while self
            .completed_order
            .front()
            .is_some_and(|(_, completed_at)| {
                now.saturating_duration_since(*completed_at) > COMPLETED_BLOCK_TTL
            })
        {
            let (block_id, _) = self.completed_order.pop_front().unwrap();
            self.completed.remove(&block_id);
        }
        expired_blocks
    }

    fn remember_completed(&mut self, block_id: u64, now: Instant) {
        if self.completed.insert(block_id) {
            self.completed_order.push_back((block_id, now));
        }
        while self.completed.len() > MAX_COMPLETED_BLOCKS {
            let (oldest, _) = self.completed_order.pop_front().unwrap();
            self.completed.remove(&oldest);
        }
    }

    fn ensure_block(&mut self, block_id: u64, now: Instant) -> anyhow::Result<&mut ReceiveBlock> {
        if !self.blocks.contains_key(&block_id) {
            ensure!(
                self.blocks.len() < MAX_RECEIVE_BLOCKS,
                "FEC receive block limit reached"
            );
            self.blocks.insert(block_id, ReceiveBlock::new(now));
        }
        Ok(self.blocks.get_mut(&block_id).unwrap())
    }

    fn remove_block(&mut self, block_id: u64, now: Instant) {
        if let Some(block) = self.blocks.remove(&block_id) {
            self.retained_bytes = self.retained_bytes.saturating_sub(block.retained_bytes);
        }
        self.remember_completed(block_id, now);
    }

    pub fn ingest_source(
        &mut self,
        block_id: u64,
        source_index: u8,
        datagram: Bytes,
        now: Instant,
    ) -> anyhow::Result<FecDecodeOutput> {
        let expired_blocks = self.expire(now);
        ensure!(block_id != 0, "FEC source block ID is zero");
        let source_index = usize::from(source_index);
        ensure!(
            source_index < FEC_SOURCE_TARGET,
            "FEC source index is out of range"
        );
        ensure!(!datagram.is_empty(), "FEC source datagram is empty");
        if self.completed.contains(&block_id) {
            return Ok(FecDecodeOutput {
                expired_blocks,
                ..Default::default()
            });
        }
        ensure!(
            self.retained_bytes.saturating_add(datagram.len()) <= MAX_RECEIVE_BYTES,
            "FEC receive byte limit reached"
        );
        let added_bytes = {
            let block = self.ensure_block(block_id, now)?;
            if let Some(source_count) = block.source_count {
                ensure!(
                    source_index < source_count,
                    "FEC source index exceeds block count"
                );
            }
            match &block.sources[source_index] {
                Some(previous) => {
                    ensure!(previous == &datagram, "FEC source bytes changed");
                    0
                }
                None => {
                    let added_bytes = datagram.len();
                    block.retained_bytes += added_bytes;
                    block.sources[source_index] = Some(datagram);
                    added_bytes
                }
            }
        };
        self.retained_bytes += added_bytes;
        let datagrams = self.try_recover(block_id, now)?;
        Ok(FecDecodeOutput {
            datagrams,
            expired_blocks,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ingest_parity(
        &mut self,
        block_id: u64,
        source_count: u8,
        parity_count: u8,
        parity_index: u8,
        shard: Bytes,
        now: Instant,
    ) -> anyhow::Result<FecDecodeOutput> {
        let expired_blocks = self.expire(now);
        let source_count = usize::from(source_count);
        let parity_count = usize::from(parity_count);
        let parity_index = usize::from(parity_index);
        ensure!(block_id != 0, "FEC parity block ID is zero");
        ensure!(
            (1..=FEC_SOURCE_TARGET).contains(&source_count),
            "invalid FEC source count"
        );
        ensure!((1..=3).contains(&parity_count), "invalid FEC parity count");
        ensure!(
            parity_index < parity_count,
            "FEC parity index is out of range"
        );
        ensure!(
            shard.len() >= 2 && shard.len().is_multiple_of(2),
            "invalid FEC parity size"
        );
        if self.completed.contains(&block_id) {
            return Ok(FecDecodeOutput {
                expired_blocks,
                ..Default::default()
            });
        }
        ensure!(
            self.retained_bytes.saturating_add(shard.len()) <= MAX_RECEIVE_BYTES,
            "FEC receive byte limit reached"
        );
        let added_bytes = {
            let block = self.ensure_block(block_id, now)?;
            if let Some(previous) = block.source_count {
                ensure!(previous == source_count, "FEC source count changed");
            }
            if let Some(previous) = block.parity_count {
                ensure!(previous == parity_count, "FEC parity count changed");
            }
            if let Some(previous) = block.shard_bytes {
                ensure!(previous == shard.len(), "FEC parity size changed");
            }
            ensure!(
                block.sources[source_count..].iter().all(Option::is_none),
                "FEC source index exceeds announced source count"
            );
            block.source_count = Some(source_count);
            block.parity_count = Some(parity_count);
            block.shard_bytes = Some(shard.len());
            match &block.parity[parity_index] {
                Some(previous) => {
                    ensure!(previous == &shard, "FEC parity bytes changed");
                    0
                }
                None => {
                    let added_bytes = shard.len();
                    block.retained_bytes += added_bytes;
                    block.parity[parity_index] = Some(shard);
                    added_bytes
                }
            }
        };
        self.retained_bytes += added_bytes;
        let datagrams = self.try_recover(block_id, now)?;
        Ok(FecDecodeOutput {
            datagrams,
            expired_blocks,
        })
    }

    fn try_recover(&mut self, block_id: u64, now: Instant) -> anyhow::Result<Vec<Bytes>> {
        let block = self.blocks.get(&block_id).unwrap();
        let (Some(source_count), Some(parity_count)) = (block.source_count, block.parity_count)
        else {
            return Ok(Vec::new());
        };
        let sources = block.sources[..source_count].to_vec();
        let missing = sources.iter().filter(|source| source.is_none()).count();
        if missing == 0 {
            self.remove_block(block_id, now);
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

        let recovered = recover_block_indexed(&sources, &parity, parity_count)?;
        let mut datagrams = Vec::with_capacity(recovered.len());
        for (_, datagram) in recovered {
            ensure!(
                matches!(
                    decode_datagram(datagram.clone()),
                    Ok(DatagramMessage::Data(_))
                ),
                "recovered FEC source is not an ETD4 data record"
            );
            datagrams.push(datagram);
        }
        self.remove_block(block_id, now);
        Ok(datagrams)
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

pub(crate) fn encode_block(sources: &[Bytes], parity_count: usize) -> anyhow::Result<Vec<Bytes>> {
    ensure!(
        (1..=16).contains(&sources.len()),
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

pub(crate) fn recover_block_indexed(
    sources: &[Option<Bytes>],
    parity: &[(usize, Bytes)],
    parity_count: usize,
) -> anyhow::Result<Vec<(usize, Bytes)>> {
    ensure!(
        (1..=16).contains(&sources.len()),
        "invalid FEC source count"
    );
    ensure!((1..=3).contains(&parity_count), "invalid FEC parity count");
    let shard_bytes = parity
        .first()
        .map(|(_, shard)| shard.len())
        .context("FEC recovery has no parity symbols")?;
    ensure!(
        shard_bytes >= 2 && shard_bytes % 2 == 0,
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

pub(super) fn recover_block(
    sources: &[Option<Bytes>],
    parity: &[Bytes],
    parity_count: usize,
) -> anyhow::Result<Vec<(usize, Bytes)>> {
    let indexed = parity.iter().cloned().enumerate().collect::<Vec<_>>();
    recover_block_indexed(sources, &indexed, parity_count)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use bytes::Bytes;

    use super::{FecDecoderState, FecEncoderState, encode_block, recover_block};
    use crate::tunnel::quic::reliable_datagram::{DatagramMessage, decode_datagram, encode_frame};

    fn sources() -> Vec<Bytes> {
        (0_u8..16)
            .map(|index| {
                let len = 80 + usize::from(index) * 7;
                Bytes::from(vec![index.wrapping_mul(17).wrapping_add(3); len])
            })
            .collect()
    }

    fn recover_with_missing(parity_count: usize, missing: &[usize]) -> anyhow::Result<Vec<Bytes>> {
        let expected = sources();
        let parity = encode_block(&expected, parity_count)?;
        let mut received = expected.iter().cloned().map(Some).collect::<Vec<_>>();
        for index in missing {
            received[*index] = None;
        }
        for (index, source) in recover_block(&received, &parity, parity_count)? {
            received[index] = Some(source);
        }
        Ok(received.into_iter().map(Option::unwrap).collect())
    }

    #[test]
    fn simd_16_plus_2_recovers_one_and_two_missing_sources() {
        let expected = sources();
        assert_eq!(recover_with_missing(2, &[7]).unwrap(), expected);
        assert_eq!(recover_with_missing(2, &[1, 14]).unwrap(), expected);
    }

    #[test]
    fn simd_16_plus_2_rejects_three_missing_but_16_plus_3_recovers() {
        assert!(recover_with_missing(2, &[2, 8, 15]).is_err());
        assert_eq!(recover_with_missing(3, &[2, 8, 15]).unwrap(), sources());
    }

    #[test]
    fn full_block_flushes_immediately_and_partial_block_waits_forty_ms() {
        let now = std::time::Instant::now();
        let mut encoder = FecEncoderState::new(2, std::time::Duration::from_millis(2)).unwrap();
        for index in 0..15 {
            let output = encoder
                .push(Bytes::from(vec![index as u8; 64]), now)
                .unwrap();
            assert!(output.completed.is_none());
        }
        let output = encoder.push(Bytes::from(vec![15; 64]), now).unwrap();
        let completed = output.completed.unwrap();
        assert_eq!(completed.source_count, 16);
        assert_eq!(completed.parity.len(), 2);

        encoder.push(Bytes::from_static(b"partial"), now).unwrap();
        assert!(
            encoder
                .flush_due(now + std::time::Duration::from_millis(1))
                .unwrap()
                .is_none()
        );
        let partial = encoder
            .flush_due(now + std::time::Duration::from_millis(2))
            .unwrap()
            .unwrap();
        assert_eq!(partial.source_count, 1);
        assert_eq!(partial.parity.len(), 2);
    }

    #[test]
    fn runtime_partial_block_deadline_preserves_16_plus_2_efficiency() {
        assert_eq!(super::FEC_FLUSH_DELAY, std::time::Duration::from_millis(40));
    }

    #[test]
    fn completed_block_cache_is_hard_bounded() {
        let now = Instant::now();
        let mut decoder = FecDecoderState::default();
        for block_id in 1..=(super::MAX_COMPLETED_BLOCKS as u64 + 1) {
            decoder.remember_completed(block_id, now);
        }

        assert_eq!(decoder.completed.len(), super::MAX_COMPLETED_BLOCKS);
        assert!(!decoder.completed.contains(&1));
        assert!(
            decoder
                .completed
                .contains(&(super::MAX_COMPLETED_BLOCKS as u64 + 1))
        );
    }

    #[test]
    fn receiver_recovers_missing_systematic_records_through_normal_etd4_bytes() {
        let now = std::time::Instant::now();
        let mut encoder = FecEncoderState::new(2, std::time::Duration::from_millis(2)).unwrap();
        let mut source_records = Vec::new();
        let mut completed = None;
        for index in 0..16_u64 {
            let inner = encode_frame(index + 1, Bytes::from(vec![index as u8; 100]), 1200)
                .unwrap()
                .remove(0);
            let output = encoder.push(inner, now).unwrap();
            source_records.push(output.source);
            completed = output.completed.or(completed);
        }
        let completed = completed.unwrap();
        let mut decoder = FecDecoderState::default();
        for (index, source) in source_records.iter().enumerate() {
            if matches!(index, 3 | 9) {
                continue;
            }
            let DatagramMessage::FecSource {
                block_id,
                source_index,
                datagram,
            } = decode_datagram(source.clone()).unwrap()
            else {
                unreachable!()
            };
            decoder
                .ingest_source(block_id, source_index, datagram, now)
                .unwrap();
        }

        let mut recovered = Vec::new();
        for parity in completed.parity {
            let DatagramMessage::FecParity {
                block_id,
                source_count,
                parity_count,
                parity_index,
                shard,
            } = decode_datagram(parity).unwrap()
            else {
                unreachable!()
            };
            recovered.extend(
                decoder
                    .ingest_parity(
                        block_id,
                        source_count,
                        parity_count,
                        parity_index,
                        shard,
                        now,
                    )
                    .unwrap()
                    .datagrams,
            );
        }
        recovered.sort_by_key(
            |datagram| match decode_datagram(datagram.clone()).unwrap() {
                DatagramMessage::Data(fragment) => fragment.frame_id,
                _ => unreachable!(),
            },
        );
        assert_eq!(recovered.len(), 2);
        assert_eq!(
            recovered
                .iter()
                .map(
                    |datagram| match decode_datagram(datagram.clone()).unwrap() {
                        DatagramMessage::Data(fragment) => fragment.frame_id,
                        _ => unreachable!(),
                    }
                )
                .collect::<Vec<_>>(),
            vec![4, 10]
        );
    }
}
