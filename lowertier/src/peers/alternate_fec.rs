use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, ensure};
use bytes::{Bytes, BytesMut};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

use crate::{
    common::global_ctx::FecResourceBudget,
    tunnel::packet_def::{
        COMPRESSOR_TAIL_SIZE, PEER_MANAGER_HEADER_SIZE, PacketType, StandardAeadTail, ZCPacket,
        ZCPacketType,
    },
};

const SOURCE_KIND: u8 = 1;
const PARITY_KIND: u8 = 2;
const SOURCE_HEADER_LEN: usize = 10;
const PARITY_HEADER_LEN: usize = 14;
const SOURCE_TARGET: usize = 16;
// The shard stores a two-byte source length and uses an even u16 shard size.
const MAX_SOURCE_BYTES: usize = u16::MAX as usize - 3;
const MAX_SHARD_BYTES: usize = MAX_SOURCE_BYTES + 2;
const MAX_BLOCKS: usize = 512;
const MAX_RETAINED_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORDS_PER_BLOCK: usize = SOURCE_TARGET + 3;
const MAX_RECOVERY_WORK_PER_SECOND: usize = 1024;
const MAX_FEC_RECORD_BYTES: usize = PARITY_HEADER_LEN + MAX_SHARD_BYTES;
const MAX_COMPLETED_BLOCKS: usize = MAX_BLOCKS;
const COMPLETED_ID_RETAINED_BYTES: usize = 64;
const RECEIVE_BLOCK_RETAINED_BYTES: usize = 512;
const BLOCK_TTL: Duration = Duration::from_secs(5);
const COMPLETED_TTL: Duration = BLOCK_TTL;
pub(crate) const FEC_FLUSH_DELAY: Duration = Duration::from_millis(40);

#[derive(Debug)]
pub(crate) struct GlobalBytesReservation {
    budget: Arc<FecResourceBudget>,
    remaining: usize,
}

fn release_budget(budget: &FecResourceBudget, bytes: usize) {
    let released = budget.release(bytes);
    if !released {
        tracing::error!(bytes, "alternate FEC budget release failed");
        debug_assert!(released, "alternate FEC budget ownership was lost");
    }
}

impl GlobalBytesReservation {
    fn new(budget: Arc<FecResourceBudget>, bytes: usize) -> anyhow::Result<Self> {
        ensure!(
            budget.reserve(bytes),
            "alternate FEC instance byte limit reached"
        );
        Ok(Self {
            budget,
            remaining: bytes,
        })
    }

    fn consume(&mut self, retained: usize) {
        self.remaining = self
            .remaining
            .checked_sub(retained)
            .expect("alternate FEC reservation released exactly once");
    }
}

impl Drop for GlobalBytesReservation {
    fn drop(&mut self) {
        release_budget(&self.budget, self.remaining);
    }
}

#[derive(Debug)]
pub(crate) struct CompletedAlternateFecBlock {
    pub block_id: u64,
    pub source_count: usize,
    pub parity: Vec<Bytes>,
    pub(crate) reservation: GlobalBytesReservation,
}

#[cfg(test)]
impl CompletedAlternateFecBlock {
    pub(crate) fn for_test(block_id: u64, source_count: usize, parity: Vec<Bytes>) -> Self {
        let retained = parity
            .iter()
            .map(|record| record.len().saturating_add(std::mem::size_of::<Bytes>()))
            .sum::<usize>()
            .saturating_add(std::mem::size_of::<Vec<Bytes>>());
        let budget = Arc::new(FecResourceBudget::with_limit(retained.max(1)));
        let reservation = GlobalBytesReservation::new(budget, retained).unwrap();
        Self {
            block_id,
            source_count,
            parity,
            reservation,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AlternateFecPushOutput {
    pub source: Bytes,
    pub completed: Option<CompletedAlternateFecBlock>,
}

pub(crate) struct AlternateFecEncoder {
    budget: Arc<FecResourceBudget>,
    metadata_reservation: GlobalBytesReservation,
    parity_count: usize,
    flush_delay: Duration,
    block_id: u64,
    stopped: bool,
    started_at: Option<Instant>,
    sources: Vec<Bytes>,
    retained_source_bytes: usize,
}

impl Drop for AlternateFecEncoder {
    fn drop(&mut self) {
        release_budget(&self.budget, self.retained_source_bytes);
    }
}

impl AlternateFecEncoder {
    pub fn new(parity_count: usize, flush_delay: Duration) -> anyhow::Result<Self> {
        Self::new_with_budget(
            parity_count,
            flush_delay,
            Arc::new(FecResourceBudget::new()),
        )
    }

    pub(crate) fn new_with_budget(
        parity_count: usize,
        flush_delay: Duration,
        budget: Arc<FecResourceBudget>,
    ) -> anyhow::Result<Self> {
        ensure!(
            (1..=3).contains(&parity_count),
            "invalid alternate FEC parity count"
        );
        ensure!(!flush_delay.is_zero(), "alternate FEC flush delay is zero");
        let metadata_bytes = std::mem::size_of::<Self>()
            .saturating_add(SOURCE_TARGET.saturating_mul(std::mem::size_of::<Bytes>()));
        let metadata_reservation = GlobalBytesReservation::new(budget.clone(), metadata_bytes)?;
        Ok(Self {
            budget,
            metadata_reservation,
            parity_count,
            flush_delay,
            block_id: 1,
            stopped: false,
            started_at: None,
            sources: Vec::with_capacity(SOURCE_TARGET),
            retained_source_bytes: 0,
        })
    }

    pub fn push(&mut self, source: Bytes, now: Instant) -> anyhow::Result<AlternateFecPushOutput> {
        ensure!(!self.stopped, "alternate FEC encoder is exhausted");
        ensure!(
            self.block_id != u64::MAX,
            "alternate FEC block ID exhausted"
        );
        ensure!(!source.is_empty(), "alternate FEC source is empty");
        let source_index = self.sources.len();
        ensure!(source_index < SOURCE_TARGET, "alternate FEC block is full");
        ensure!(
            source.len() <= MAX_SOURCE_BYTES,
            "alternate FEC source symbol is too large"
        );
        let retained = source.len().saturating_add(std::mem::size_of::<Bytes>());
        ensure!(
            self.budget.reserve(retained),
            "alternate FEC encoder byte limit reached"
        );
        let source_record = match encode_source(self.block_id, source_index, source.clone()) {
            Ok(record) => record,
            Err(error) => {
                release_budget(&self.budget, retained);
                return Err(error);
            }
        };
        if self.sources.is_empty() {
            self.started_at = Some(now);
        }
        self.sources.push(source);
        self.retained_source_bytes = self.retained_source_bytes.saturating_add(retained);
        let completed = (self.sources.len() == SOURCE_TARGET)
            .then(|| self.flush())
            .transpose()?;
        Ok(AlternateFecPushOutput {
            source: source_record,
            completed,
        })
    }

    pub fn flush_due(&mut self, now: Instant) -> anyhow::Result<CompletedAlternateFecBlock> {
        ensure!(!self.stopped, "alternate FEC encoder is exhausted");
        ensure!(!self.sources.is_empty(), "alternate FEC block is empty");
        ensure!(
            self.started_at
                .is_some_and(|started| now.saturating_duration_since(started) >= self.flush_delay),
            "alternate FEC block is not due"
        );
        self.flush()
    }

    pub fn take_due(&mut self, now: Instant) -> anyhow::Result<Option<CompletedAlternateFecBlock>> {
        ensure!(!self.stopped, "alternate FEC encoder is exhausted");
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

    pub(crate) fn record_lengths_for_source(
        &self,
        source_payload_len: usize,
    ) -> Option<(usize, usize)> {
        if source_payload_len > MAX_SOURCE_BYTES {
            return None;
        }
        let longest = self
            .sources
            .iter()
            .map(Bytes::len)
            .max()
            .unwrap_or(0)
            .max(source_payload_len);
        let shard_len = longest.checked_add(2)?.next_multiple_of(2);
        Some((
            SOURCE_HEADER_LEN.checked_add(source_payload_len)?,
            PARITY_HEADER_LEN.checked_add(shard_len)?,
        ))
    }

    fn flush(&mut self) -> anyhow::Result<CompletedAlternateFecBlock> {
        let block_id = self.block_id;
        let source_count = self.sources.len();
        let next_block_id = self.block_id.checked_add(1);
        let block_id_exhausted = next_block_id.is_none();
        let parity_reservation = shard_bytes(&self.sources).and_then(|shard_bytes| {
            let record_bytes = PARITY_HEADER_LEN
                .checked_add(shard_bytes)
                .context("alternate FEC parity record size overflow")?;
            let retained_per_parity = record_bytes
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Bytes>()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ZCPacket>()))
                .context("alternate FEC parity retention size overflow")?;
            let retained = retained_per_parity
                .checked_mul(self.parity_count)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<Bytes>>()))
                .context("alternate FEC parity retention size overflow")?;
            GlobalBytesReservation::new(self.budget.clone(), retained)
        });
        let result = next_block_id
            .ok_or_else(|| anyhow::anyhow!("alternate FEC block ID exhausted"))
            .and_then(|next_block_id| {
                let reservation = parity_reservation?;
                encode_block(&self.sources, self.parity_count).and_then(|parity| {
                    parity
                        .into_iter()
                        .enumerate()
                        .map(|(index, shard)| {
                            encode_parity(block_id, source_count, self.parity_count, index, shard)
                        })
                        .collect::<anyhow::Result<Vec<_>>>()
                        .map(|parity| (next_block_id, parity, reservation))
                })
            });
        self.sources.clear();
        release_budget(&self.budget, self.retained_source_bytes);
        self.retained_source_bytes = 0;
        self.started_at = None;
        match result {
            Ok((next_block_id, parity, reservation)) => {
                self.block_id = next_block_id;
                Ok(CompletedAlternateFecBlock {
                    block_id,
                    source_count,
                    parity,
                    reservation,
                })
            }
            Err(error) => {
                if block_id_exhausted {
                    self.stopped = true;
                }
                Err(error)
            }
        }
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
    ensure!(
        source.len() <= MAX_SOURCE_BYTES,
        "alternate FEC source symbol is too large"
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
        (2..=MAX_SHARD_BYTES).contains(&shard.len()) && shard.len().is_multiple_of(2),
        "alternate FEC parity shard size is invalid"
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
        record.len() <= MAX_FEC_RECORD_BYTES,
        "alternate FEC record exceeds the QUIC datagram bound"
    );
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
            ensure!(
                record.len() - SOURCE_HEADER_LEN <= MAX_SOURCE_BYTES,
                "alternate FEC source symbol is too large"
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
                (2..=MAX_SHARD_BYTES).contains(&shard_len) && shard_len.is_multiple_of(2),
                "invalid alternate FEC shard size"
            );
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
        (2..=MAX_SHARD_BYTES).contains(&shard_bytes) && shard_bytes.is_multiple_of(2),
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
            (1..=MAX_SOURCE_BYTES).contains(&encoded_len) && encoded_len + 2 <= shard.len(),
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
    records_seen: usize,
    retained_bytes: usize,
    metadata_charged: bool,
    expires_at: Instant,
}

impl ReceiveBlock {
    fn new(now: Instant) -> Self {
        Self {
            sources: vec![None; SOURCE_TARGET],
            parity: vec![None; 3],
            source_count: None,
            parity_count: None,
            records_seen: 0,
            retained_bytes: 0,
            metadata_charged: false,
            expires_at: now.checked_add(BLOCK_TTL).unwrap_or(now),
        }
    }
}

#[derive(Default)]
pub(crate) struct AlternateFecDecodeOutput {
    pub datagrams: Vec<Bytes>,
    pub expired_blocks: usize,
    pub direct_source_index: Option<usize>,
}

pub(crate) struct AlternateFecDecoder {
    budget: Arc<FecResourceBudget>,
    blocks: HashMap<u64, ReceiveBlock>,
    expiry_index: BTreeSet<(Instant, u64)>,
    retained_bytes: usize,
    completed: HashSet<u64>,
    completed_order: VecDeque<(Instant, u64)>,
    completed_retained_bytes: usize,
    cpu_window_started_at: Option<Instant>,
    cpu_work_used: usize,
}

impl Default for AlternateFecDecoder {
    fn default() -> Self {
        Self::new(Arc::new(FecResourceBudget::new()))
    }
}

impl Drop for AlternateFecDecoder {
    fn drop(&mut self) {
        let block_metadata_bytes = self
            .blocks
            .values()
            .filter(|block| block.metadata_charged)
            .count()
            * RECEIVE_BLOCK_RETAINED_BYTES;
        release_budget(&self.budget, self.retained_bytes + block_metadata_bytes);
        release_budget(&self.budget, self.completed_retained_bytes);
    }
}

impl AlternateFecDecoder {
    pub(crate) fn new(budget: Arc<FecResourceBudget>) -> Self {
        Self {
            budget,
            blocks: HashMap::new(),
            expiry_index: BTreeSet::new(),
            retained_bytes: 0,
            completed: HashSet::new(),
            completed_order: VecDeque::new(),
            completed_retained_bytes: 0,
            cpu_window_started_at: None,
            cpu_work_used: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(limit: usize) -> Self {
        Self::new(Arc::new(FecResourceBudget::with_limit(limit)))
    }

    pub fn ingest(
        &mut self,
        record: Bytes,
        now: Instant,
    ) -> anyhow::Result<AlternateFecDecodeOutput> {
        let expired_blocks = self.expire(now);
        let mut datagrams = Vec::new();
        let mut direct_source_index = None;
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
                let mut global_reservation =
                    GlobalBytesReservation::new(self.budget.clone(), datagram.len())?;
                let added = {
                    let block = match self.ensure_block(block_id, now) {
                        Ok(block) => block,
                        Err(error) => return Err(error),
                    };
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
                            if block.records_seen >= MAX_RECORDS_PER_BLOCK {
                                anyhow::bail!("alternate FEC record limit reached");
                            }
                            block.records_seen += 1;
                            let len = datagram.len();
                            block.sources[source_index] = Some(datagram.clone());
                            block.retained_bytes += len;
                            direct_source_index = Some(datagrams.len());
                            datagrams.push(datagram);
                            len
                        }
                    }
                };
                global_reservation.consume(added);
                self.retained_bytes = self
                    .retained_bytes
                    .checked_add(added)
                    .expect("alternate FEC retained byte accounting overflow");
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
                let mut global_reservation =
                    GlobalBytesReservation::new(self.budget.clone(), shard.len())?;
                let added = {
                    let block = match self.ensure_block(block_id, now) {
                        Ok(block) => block,
                        Err(error) => return Err(error),
                    };
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
                            if block.records_seen >= MAX_RECORDS_PER_BLOCK {
                                anyhow::bail!("alternate FEC record limit reached");
                            }
                            block.records_seen += 1;
                            let len = shard.len();
                            block.parity[parity_index] = Some(shard);
                            block.retained_bytes += len;
                            len
                        }
                    }
                };
                global_reservation.consume(added);
                self.retained_bytes = self
                    .retained_bytes
                    .checked_add(added)
                    .expect("alternate FEC retained byte accounting overflow");
                datagrams.extend(self.try_recover(block_id, now)?);
            }
        }
        Ok(AlternateFecDecodeOutput {
            datagrams,
            expired_blocks,
            direct_source_index,
        })
    }

    fn ensure_block(&mut self, block_id: u64, now: Instant) -> anyhow::Result<&mut ReceiveBlock> {
        if !self.blocks.contains_key(&block_id) {
            ensure!(
                self.blocks.len() < MAX_BLOCKS,
                "alternate FEC block limit reached"
            );
            ensure!(
                self.budget.reserve(RECEIVE_BLOCK_RETAINED_BYTES),
                "alternate FEC block metadata limit reached"
            );
            let mut block = ReceiveBlock::new(now);
            block.metadata_charged = true;
            self.expiry_index.insert((block.expires_at, block_id));
            self.blocks.insert(block_id, block);
        }
        Ok(self.blocks.get_mut(&block_id).unwrap())
    }

    fn try_recover(&mut self, block_id: u64, now: Instant) -> anyhow::Result<Vec<Bytes>> {
        if self
            .cpu_window_started_at
            .is_none_or(|started| now.saturating_duration_since(started) >= Duration::from_secs(1))
        {
            self.cpu_window_started_at = Some(now);
            self.cpu_work_used = 0;
        }
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
        let work = missing.saturating_mul(parity_count).max(1);
        ensure!(
            self.cpu_work_used.saturating_add(work) <= MAX_RECOVERY_WORK_PER_SECOND,
            "alternate FEC recovery work limit reached"
        );
        self.cpu_work_used += work;
        let recovered = recover_block_indexed(&sources, &parity, parity_count)?
            .into_iter()
            .map(|(_, datagram)| datagram)
            .collect();
        self.complete(block_id, now);
        Ok(recovered)
    }

    fn complete(&mut self, block_id: u64, now: Instant) {
        if let Some(block) = self.blocks.remove(&block_id) {
            self.expiry_index.remove(&(block.expires_at, block_id));
            self.retained_bytes = self
                .retained_bytes
                .checked_sub(block.retained_bytes)
                .expect("alternate FEC block bytes were released once");
            release_budget(
                &self.budget,
                block.retained_bytes
                    + usize::from(block.metadata_charged) * RECEIVE_BLOCK_RETAINED_BYTES,
            );
        }
        if !self.completed.contains(&block_id) && self.budget.reserve(COMPLETED_ID_RETAINED_BYTES) {
            let inserted = self.completed.insert(block_id);
            debug_assert!(inserted);
            if inserted {
                self.completed_retained_bytes = self
                    .completed_retained_bytes
                    .checked_add(COMPLETED_ID_RETAINED_BYTES)
                    .expect("completed FEC ID bytes fit the decoder budget accounting");
                self.completed_order.push_back((now, block_id));
            } else {
                release_budget(&self.budget, COMPLETED_ID_RETAINED_BYTES);
            }
        }
        while self.completed.len() > MAX_COMPLETED_BLOCKS {
            let (_, oldest) = self
                .completed_order
                .pop_front()
                .expect("completed FEC ID index matches the set");
            let removed = self.completed.remove(&oldest);
            debug_assert!(removed);
            if removed {
                self.completed_retained_bytes = self
                    .completed_retained_bytes
                    .checked_sub(COMPLETED_ID_RETAINED_BYTES)
                    .expect("completed FEC ID bytes were released once");
                release_budget(&self.budget, COMPLETED_ID_RETAINED_BYTES);
            }
        }
    }

    fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0;
        while let Some(&(expires_at, block_id)) = self.expiry_index.first() {
            if expires_at > now {
                break;
            }
            self.expiry_index.remove(&(expires_at, block_id));
            if let Some(block) = self.blocks.remove(&block_id) {
                expired += 1;
                self.retained_bytes = self
                    .retained_bytes
                    .checked_sub(block.retained_bytes)
                    .expect("expired alternate FEC block bytes were released once");
                release_budget(
                    &self.budget,
                    block.retained_bytes
                        + usize::from(block.metadata_charged) * RECEIVE_BLOCK_RETAINED_BYTES,
                );
            }
        }
        while self
            .completed_order
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > COMPLETED_TTL)
        {
            let (_, block_id) = self
                .completed_order
                .pop_front()
                .expect("completed FEC ID index has a head");
            let removed = self.completed.remove(&block_id);
            debug_assert!(removed);
            if removed {
                self.completed_retained_bytes = self
                    .completed_retained_bytes
                    .checked_sub(COMPLETED_ID_RETAINED_BYTES)
                    .expect("expired completed FEC ID bytes were released once");
                release_budget(&self.budget, COMPLETED_ID_RETAINED_BYTES);
            }
        }
        expired
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AlternateFecSourceMetadata {
    from_peer_id: u32,
    to_peer_id: u32,
    flow_shard: Option<u16>,
    flow_hash: Option<u64>,
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
        flow_hash: packet.flow_hash(),
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
    if let Some(flow_hash) = metadata.flow_hash {
        wrapped.set_flow_hash(flow_hash);
    }
    wrapped
}

pub(crate) fn parity_packets(
    from_peer_id: u32,
    immediate_peer_id: u32,
    block: &CompletedAlternateFecBlock,
) -> Vec<ZCPacket> {
    block
        .parity
        .iter()
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
    let flow_hash = packet.flow_hash();
    let session_peer_id = packet.authenticated_peer_id();
    let session_peer_identity_type = packet.authenticated_peer_identity_type();
    let session_peer_secure_auth_level = packet.authenticated_peer_secure_auth_level();
    let authenticated_session_id = packet.authenticated_session_id();
    ensure!(
        packet_type == PacketType::AlternateFecSource as u8
            || packet_type == PacketType::AlternateFecParity as u8,
        "packet is not an alternate FEC record"
    );
    let decoded = decoder.ingest(packet.payload_bytes().freeze(), now)?;
    let direct_source_index = decoded.direct_source_index;
    decoded
        .datagrams
        .into_iter()
        .enumerate()
        .map(|(index, datagram)| {
            ensure!(
                datagram.len() >= PEER_MANAGER_HEADER_SIZE,
                "recovered alternate FEC packet is too short"
            );
            let is_source_datagram = direct_source_index == Some(index);
            let buffer = datagram
                .try_into_mut()
                .unwrap_or_else(|shared| BytesMut::from(shared.as_ref()));
            let mut packet = ZCPacket::new_from_buf(buffer, ZCPacketType::DummyTunnel);
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
            if let Some(peer_id) = session_peer_id {
                ensure!(
                    packet.set_authenticated_peer_id(peer_id),
                    "recovered alternate FEC packet has conflicting session identity"
                );
            }
            if let Some(identity_type) = session_peer_identity_type {
                ensure!(
                    packet.set_authenticated_peer_identity_type(identity_type),
                    "recovered alternate FEC packet has conflicting session role"
                );
            }
            if let Some(secure_auth_level) = session_peer_secure_auth_level {
                ensure!(
                    packet.set_authenticated_peer_secure_auth_level(secure_auth_level),
                    "recovered alternate FEC packet has conflicting authentication level"
                );
            }
            if let Some(session_id) = authenticated_session_id {
                ensure!(
                    packet.set_authenticated_session_id(session_id),
                    "recovered alternate FEC packet has conflicting session ID"
                );
            }
            if let Some(flow_hash) = flow_hash
                && is_source_datagram
            {
                packet.set_flow_hash(flow_hash);
            }
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
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use bytes::Bytes;

    use super::{
        AlternateFecDecoder, AlternateFecEncoder, BLOCK_TTL, COMPLETED_ID_RETAINED_BYTES,
        COMPLETED_TTL, MAX_BLOCKS, MAX_SHARD_BYTES, MAX_SOURCE_BYTES, PARITY_HEADER_LEN,
        RECEIVE_BLOCK_RETAINED_BYTES, SOURCE_HEADER_LEN, SOURCE_KIND, decode_alternate_fec_packet,
        parity_packets, source_metadata, wrap_source_packet,
    };
    use crate::common::global_ctx::FecResourceBudget;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
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
    fn maximum_source_size_65532_is_accepted() {
        assert_eq!(MAX_SOURCE_BYTES, 65_532);
        let now = Instant::now();
        let mut encoder = AlternateFecEncoder::new(1, Duration::from_millis(40)).unwrap();
        let output = encoder
            .push(Bytes::from(vec![0x5a; MAX_SOURCE_BYTES]), now)
            .unwrap();
        assert!(output.completed.is_none());
        assert_eq!(
            encoder.next_flush_at(),
            Some(now + Duration::from_millis(40))
        );

        let block = encoder.flush_due(now + Duration::from_millis(40)).unwrap();
        assert_eq!(block.source_count, 1);
        assert_eq!(block.parity.len(), 1);
        assert_eq!(block.parity[0].len(), PARITY_HEADER_LEN + MAX_SHARD_BYTES);
    }

    #[test]
    fn source_size_65533_is_rejected_before_encoder_state_changes() {
        let now = Instant::now();
        let mut encoder = AlternateFecEncoder::new(1, Duration::from_millis(40)).unwrap();
        let error = encoder
            .push(Bytes::from(vec![0x5a; MAX_SOURCE_BYTES + 1]), now)
            .unwrap_err();
        assert!(error.to_string().contains("source symbol is too large"));
        assert_eq!(encoder.next_flush_at(), None);
    }

    #[test]
    fn failed_flush_drops_the_block_and_deadline() {
        let now = Instant::now();
        let mut encoder = AlternateFecEncoder::new(1, Duration::from_millis(40)).unwrap();
        encoder
            .sources
            .push(Bytes::from(vec![0x5a; MAX_SOURCE_BYTES + 1]));
        encoder.started_at = Some(now);

        let error = encoder
            .flush_due(now + Duration::from_millis(40))
            .unwrap_err();
        assert!(error.to_string().contains("FEC source symbol is too large"));
        assert_eq!(encoder.next_flush_at(), None);
        assert!(encoder.sources.is_empty());
        assert!(
            encoder
                .take_due(now + Duration::from_secs(1))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn block_id_exhaustion_stops_without_wrapping() {
        let now = Instant::now();
        let mut encoder = AlternateFecEncoder::new(1, Duration::from_millis(40)).unwrap();
        encoder.block_id = u64::MAX;
        encoder.sources.push(Bytes::from_static(b"pending source"));
        encoder.started_at = Some(now);

        let error = encoder
            .flush_due(now + Duration::from_millis(40))
            .unwrap_err();
        assert!(error.to_string().contains("block ID exhausted"));
        assert!(encoder.stopped);
        assert_eq!(encoder.block_id, u64::MAX);
        assert!(encoder.sources.is_empty());
        assert!(encoder.push(Bytes::from_static(b"next"), now).is_err());
    }

    #[test]
    fn expiry_index_handles_the_full_block_bound() {
        let now = Instant::now();
        let mut decoder = AlternateFecDecoder::default();
        for block_id in 1..=MAX_BLOCKS as u64 {
            let block = super::ReceiveBlock::new(now);
            decoder.expiry_index.insert((block.expires_at, block_id));
            decoder.blocks.insert(block_id, block);
        }
        assert_eq!(decoder.blocks.len(), MAX_BLOCKS);
        assert_eq!(decoder.expire(now + BLOCK_TTL), MAX_BLOCKS);
        assert!(decoder.blocks.is_empty());
        assert!(decoder.expiry_index.is_empty());
    }

    #[test]
    fn separate_decoder_instances_have_isolated_resource_budgets() {
        let now = Instant::now();
        let retained = RECEIVE_BLOCK_RETAINED_BYTES + 32;
        let first_budget = Arc::new(FecResourceBudget::with_limit(retained));
        let second_budget = Arc::new(FecResourceBudget::with_limit(retained));
        let mut first = AlternateFecDecoder::new(first_budget.clone());
        let mut second = AlternateFecDecoder::new(second_budget.clone());
        let record = super::encode_source(1, 0, Bytes::from(vec![0x5a; 32])).unwrap();

        first.ingest(record.clone(), now).unwrap();
        second.ingest(record, now).unwrap();
        assert_eq!(first_budget.retained(), retained);
        assert_eq!(second_budget.retained(), retained);
    }

    #[test]
    fn global_contexts_do_not_share_fec_resource_budgets() {
        let first_ctx = get_mock_global_ctx();
        let second_ctx = get_mock_global_ctx();
        let first_budget = first_ctx.fec_resource_budget();
        let second_budget = second_ctx.fec_resource_budget();

        assert!(!Arc::ptr_eq(&first_budget, &second_budget));
        assert!(first_budget.reserve(32));
        assert!(second_budget.reserve(32));
        assert!(first_budget.release(32));
        assert!(second_budget.release(32));
    }

    #[test]
    fn decoders_sharing_one_instance_budget_are_bounded_together() {
        let now = Instant::now();
        let retained = RECEIVE_BLOCK_RETAINED_BYTES + 32;
        let shared_budget = Arc::new(FecResourceBudget::with_limit(retained));
        let mut first = AlternateFecDecoder::new(shared_budget.clone());
        let mut second = AlternateFecDecoder::new(shared_budget.clone());
        let first_record = super::encode_source(1, 0, Bytes::from(vec![0x5a; 32])).unwrap();
        let second_record = super::encode_source(2, 0, Bytes::from(vec![0xa5; 32])).unwrap();

        first.ingest(first_record, now).unwrap();
        assert!(second.ingest(second_record, now).is_err());
        assert_eq!(shared_budget.retained(), retained);
    }

    #[test]
    fn source_origin_is_carried_from_the_single_record_decode() {
        let now = Instant::now();
        let source = Bytes::from_static(b"source-payload");
        let record = super::encode_source(1, 0, source.clone()).unwrap();
        let mut decoder = AlternateFecDecoder::default();

        let output = decoder.ingest(record, now).unwrap();
        assert_eq!(output.direct_source_index, Some(0));
        assert_eq!(output.datagrams, vec![source]);
    }

    #[test]
    fn completed_id_budget_is_shared_and_released_by_short_ttl() {
        let now = Instant::now();
        let budget = Arc::new(FecResourceBudget::with_limit(
            COMPLETED_ID_RETAINED_BYTES * 2,
        ));
        let mut first = AlternateFecDecoder::new(budget.clone());
        let mut second = AlternateFecDecoder::new(budget.clone());

        first.complete(1, now);
        second.complete(2, now);
        assert_eq!(budget.retained(), COMPLETED_ID_RETAINED_BYTES * 2);
        first.complete(3, now);
        assert_eq!(first.completed.len(), 1);
        assert_eq!(second.completed.len(), 1);

        assert_eq!(first.expire(now + COMPLETED_TTL), 0);
        assert_eq!(budget.retained(), COMPLETED_ID_RETAINED_BYTES * 2);
        assert_eq!(
            first.expire(now + COMPLETED_TTL + Duration::from_nanos(1)),
            0
        );
        assert_eq!(budget.retained(), COMPLETED_ID_RETAINED_BYTES);
    }

    #[test]
    fn many_decoder_completed_ids_stop_at_the_shared_budget() {
        let now = Instant::now();
        let budget = Arc::new(FecResourceBudget::with_limit(
            COMPLETED_ID_RETAINED_BYTES * 4,
        ));
        let mut decoders = (0..8)
            .map(|_| AlternateFecDecoder::new(budget.clone()))
            .collect::<Vec<_>>();

        for (block_id, decoder) in decoders.iter_mut().enumerate() {
            decoder.complete(block_id as u64 + 1, now);
        }

        assert_eq!(budget.retained(), COMPLETED_ID_RETAINED_BYTES * 4);
        assert_eq!(
            decoders
                .iter()
                .map(|decoder| decoder.completed.len())
                .sum::<usize>(),
            4
        );
    }

    #[test]
    fn changed_parity_record_is_rejected_before_recovery() {
        let now = Instant::now();
        let expected = sources(16);
        let mut encoder = AlternateFecEncoder::new(1, Duration::from_millis(40)).unwrap();
        let mut source_records = Vec::new();
        let mut completed = None;
        for source in &expected {
            let output = encoder.push(source.clone(), now).unwrap();
            source_records.push(output.source);
            completed = output.completed.or(completed);
        }
        let completed = completed
            .unwrap_or_else(|| encoder.flush_due(now + Duration::from_millis(40)).unwrap());
        let parity = parity_packets(11, 22, &completed)
        .pop()
        .unwrap();
        let mut decoder = AlternateFecDecoder::default();
        decoder.ingest(source_records.remove(0), now).unwrap();
        decoder
            .ingest(parity.clone().payload_bytes().freeze(), now)
            .unwrap();
        let mut changed = parity;
        changed.mut_payload_preserving_flow_hash()[PARITY_HEADER_LEN] ^= 1;
        assert!(
            decoder
                .ingest(changed.payload_bytes().freeze(), now)
                .is_err()
        );
    }

    #[test]
    fn packet_wrapper_round_trip_preserves_header_payload_and_markers() {
        let now = Instant::now();
        let flow_hash = 0x0123_4567_89ab_cdef;
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
        original.set_flow_hash(flow_hash);
        let expected = original.tunnel_payload().to_vec();

        let mut encoder = AlternateFecEncoder::new(2, Duration::from_millis(40)).unwrap();
        let encoded = encoder
            .push(Bytes::copy_from_slice(original.tunnel_payload()), now)
            .unwrap();
        let wrapped = wrap_source_packet(source_metadata(&original).unwrap(), encoded.source);
        let mut wrapped = wrapped;
        let session_id = uuid::Uuid::new_v4();
        assert!(wrapped.set_authenticated_peer_id(11));
        assert!(
            wrapped.set_authenticated_peer_identity_type(
                crate::proto::peer_rpc::PeerIdentityType::Admin
            )
        );
        assert!(wrapped.set_authenticated_peer_secure_auth_level(
            crate::proto::peer_rpc::SecureAuthLevel::NetworkSecretConfirmed
        ));
        assert!(wrapped.set_authenticated_session_id(session_id));
        let wrapped_header = wrapped.peer_manager_header().unwrap();
        assert_eq!(
            wrapped_header.packet_type,
            PacketType::AlternateFecSource as u8
        );
        assert_eq!(wrapped_header.flow_shard(), Some(17));
        assert!(wrapped_header.is_critical_l2_control());
        assert_eq!(wrapped.flow_hash(), Some(flow_hash));

        let mut decoder = AlternateFecDecoder::default();
        let recovered = decode_alternate_fec_packet(wrapped, &mut decoder, now).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].tunnel_payload(), expected);
        assert_eq!(recovered[0].flow_hash(), Some(flow_hash));
        assert_eq!(recovered[0].authenticated_peer_id(), Some(11));
        assert_eq!(recovered[0].authenticated_session_id(), Some(session_id));
        assert_eq!(
            recovered[0].authenticated_peer_identity_type(),
            Some(crate::proto::peer_rpc::PeerIdentityType::Admin)
        );
        assert_eq!(
            recovered[0].authenticated_peer_secure_auth_level(),
            Some(crate::proto::peer_rpc::SecureAuthLevel::NetworkSecretConfirmed)
        );
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
        let completed = completed.unwrap();
        let packets = parity_packets(31, 47, &completed);
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
