use std::{
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use atomic_shim::AtomicU64;
use hmac::{Hmac, Mac as _};
use rand::RngCore as _;
use sha2::Sha256;
use smallvec::SmallVec;
use zerocopy::FromBytes;

use crate::{
    peers::{
        encrypt::{Encryptor, create_secure_datagram_encryptor},
        replay_window::ReplayWindow,
    },
    tunnel::packet_def::{PEER_MANAGER_STABLE_AUTH_DATA_SIZE, StandardAeadTail, ZCPacket},
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureDatagramDirection {
    AToB,
    BToA,
}

impl SecureDatagramDirection {
    fn idx(self) -> usize {
        match self {
            Self::AToB => 0,
            Self::BToA => 1,
        }
    }
}

#[derive(Clone, Default)]
struct EpochKeySlot {
    epoch: u32,
    generation: u32,
    valid: bool,
    send_cipher: Option<Arc<dyn Encryptor>>,
    recv_cipher: Option<Arc<dyn Encryptor>>,
}

impl std::fmt::Debug for EpochKeySlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochKeySlot")
            .field("epoch", &self.epoch)
            .field("generation", &self.generation)
            .field("valid", &self.valid)
            .finish()
    }
}

impl EpochKeySlot {
    fn get_encryptor(&self, is_send: bool) -> Arc<dyn Encryptor> {
        if is_send {
            self.send_cipher.as_ref().unwrap().clone()
        } else {
            self.recv_cipher.as_ref().unwrap().clone()
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct EpochRxSlot {
    epoch: u32,
    window: ReplayWindow,
    last_rx_ms: u64,
    valid: bool,
}

impl EpochRxSlot {
    fn clear(&mut self) {
        self.epoch = 0;
        self.window.clear();
        self.last_rx_ms = 0;
        self.valid = false;
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SyncRxGrace {
    slots: [[EpochRxSlot; 2]; 2],
    expires_at_ms: u64,
    valid: bool,
}

impl SyncRxGrace {
    fn clear(&mut self) {
        self.slots = [[EpochRxSlot::default(), EpochRxSlot::default()]; 2];
        self.expires_at_ms = 0;
        self.valid = false;
    }

    fn refresh(&mut self, slots: [[EpochRxSlot; 2]; 2], expires_at_ms: u64) {
        self.slots = slots;
        self.expires_at_ms = expires_at_ms;
        self.valid = true;
    }

    fn maybe_expire(&mut self, now_ms: u64) {
        if self.valid && now_ms >= self.expires_at_ms {
            self.clear();
        }
    }
}

pub struct SecureDatagramSession {
    state_transition: RwLock<()>,
    root_key: RwLock<[u8; 32]>,
    session_generation: AtomicU32,

    send_epoch: AtomicU32,
    send_seq: [AtomicU64; 2],
    send_epoch_started_ms: AtomicU64,
    send_packets_since_epoch: AtomicU64,
    rotation_lock: Mutex<()>,

    rx_slots: Mutex<[[EpochRxSlot; 2]; 2]>,
    key_cache: Mutex<[[EpochKeySlot; 2]; 2]>,
    sync_rx_grace: Mutex<SyncRxGrace>,
    sync_rx_grace_expires_at_ms: AtomicU64,

    send_cipher_algorithm: String,
    recv_cipher_algorithm: String,

    invalidated: AtomicBool,
    decrypt_fail_count: AtomicU32,
}

struct RedactedSecret;

impl std::fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::fmt::Debug for SecureDatagramSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureDatagramSession")
            .field("root_key", &RedactedSecret)
            .field("session_generation", &self.session_generation)
            .field("send_epoch", &self.send_epoch)
            .field("send_seq", &self.send_seq)
            .field("send_epoch_started_ms", &self.send_epoch_started_ms)
            .field("send_packets_since_epoch", &self.send_packets_since_epoch)
            .field("rx_slots", &self.rx_slots)
            .field("key_cache", &self.key_cache)
            .field("sync_rx_grace", &self.sync_rx_grace)
            .field(
                "sync_rx_grace_expires_at_ms",
                &self.sync_rx_grace_expires_at_ms,
            )
            .field("send_cipher_algorithm", &self.send_cipher_algorithm)
            .field("recv_cipher_algorithm", &self.recv_cipher_algorithm)
            .finish()
    }
}

impl SecureDatagramSession {
    pub(crate) const SYNC_RX_GRACE_AFTER_MS: u64 = 5_000;
    const ROTATE_AFTER_PACKETS: u64 = 1_000_000;
    const ROTATE_AFTER_MS: u64 = 10 * 60 * 1000;
    const MAX_ACCEPTED_RX_EPOCH_AHEAD: u32 = 3;
    const DECRYPT_FAIL_THRESHOLD: u32 = 10;

    pub fn new(
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        send_cipher_algorithm: String,
        recv_cipher_algorithm: String,
    ) -> Self {
        let rx_slots = [
            [EpochRxSlot::default(), EpochRxSlot::default()],
            [EpochRxSlot::default(), EpochRxSlot::default()],
        ];
        let key_cache = [
            [EpochKeySlot::default(), EpochKeySlot::default()],
            [EpochKeySlot::default(), EpochKeySlot::default()],
        ];
        let now_ms = now_ms();
        Self {
            state_transition: RwLock::new(()),
            root_key: RwLock::new(root_key),
            session_generation: AtomicU32::new(session_generation),
            send_epoch: AtomicU32::new(initial_epoch),
            send_seq: [AtomicU64::new(0), AtomicU64::new(0)],
            send_epoch_started_ms: AtomicU64::new(now_ms),
            send_packets_since_epoch: AtomicU64::new(0),
            rotation_lock: Mutex::new(()),
            rx_slots: Mutex::new(rx_slots),
            key_cache: Mutex::new(key_cache),
            sync_rx_grace: Mutex::new(SyncRxGrace::default()),
            sync_rx_grace_expires_at_ms: AtomicU64::new(0),
            send_cipher_algorithm,
            recv_cipher_algorithm,
            invalidated: AtomicBool::new(false),
            decrypt_fail_count: AtomicU32::new(0),
        }
    }

    pub fn invalidate(&self) {
        self.invalidated.store(true, Ordering::Relaxed);
    }

    pub fn is_valid(&self) -> bool {
        !self.invalidated.load(Ordering::Relaxed)
    }

    /// Record one failed decrypt operation without changing authenticated state.
    fn record_decrypt_failure(&self) {
        let previous = self
            .decrypt_fail_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(1).min(Self::DECRYPT_FAIL_THRESHOLD))
            })
            .unwrap_or(Self::DECRYPT_FAIL_THRESHOLD);
        let count = previous.saturating_add(1).min(Self::DECRYPT_FAIL_THRESHOLD);
        if previous < Self::DECRYPT_FAIL_THRESHOLD && count == Self::DECRYPT_FAIL_THRESHOLD {
            tracing::warn!(count, "secure datagram decrypt failure threshold reached");
        }
    }

    /// Clear the failure streak only after an authenticated packet is accepted.
    fn record_authenticated_success(&self) {
        self.decrypt_fail_count.store(0, Ordering::Release);
    }



    pub fn session_generation(&self) -> u32 {
        self.session_generation.load(Ordering::Relaxed)
    }

    pub fn root_key(&self) -> [u8; 32] {
        *self.root_key.read().unwrap()
    }

    pub fn new_root_key() -> [u8; 32] {
        let mut out = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut out);
        out
    }

    pub fn next_sync_epoch(&self) -> u32 {
        let send_epoch = self.send_epoch.load(Ordering::Relaxed);
        let rx = self.rx_slots.lock().unwrap();
        let mut max_epoch = send_epoch;
        for dir in 0..2 {
            let cur = rx[dir][0];
            if cur.valid {
                max_epoch = max_epoch.max(cur.epoch);
            }
            let prev = rx[dir][1];
            if prev.valid {
                max_epoch = max_epoch.max(prev.epoch);
            }
        }
        max_epoch.wrapping_add(1)
    }

    pub fn check_encrypt_algo_same(
        &self,
        send_algorithm: &str,
        recv_algorithm: &str,
    ) -> Result<(), anyhow::Error> {
        if self.send_cipher_algorithm != send_algorithm
            || self.recv_cipher_algorithm != recv_algorithm
        {
            return Err(anyhow!("encrypt algorithm not same"));
        }
        Ok(())
    }

    pub fn sync_root_key(
        &self,
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        preserve_rx_grace: bool,
    ) {
        let _transition_guard = self.state_transition.write().unwrap();
        let old_root_key = self.root_key();
        let can_preserve_rx_grace = preserve_rx_grace && old_root_key == root_key;
        {
            let mut g = self.root_key.write().unwrap();
            *g = root_key;
        }
        self.session_generation
            .store(session_generation, Ordering::Relaxed);

        self.send_epoch.store(initial_epoch, Ordering::Relaxed);
        self.send_seq[0].store(0, Ordering::Relaxed);
        self.send_seq[1].store(0, Ordering::Relaxed);
        self.send_epoch_started_ms
            .store(now_ms(), Ordering::Relaxed);
        self.send_packets_since_epoch.store(0, Ordering::Relaxed);

        {
            let mut rx = self.rx_slots.lock().unwrap();
            let mut sync_rx_grace = self.sync_rx_grace.lock().unwrap();
            if can_preserve_rx_grace {
                let expires_at_ms = now_ms().saturating_add(Self::SYNC_RX_GRACE_AFTER_MS);
                let mut previous_slots = *rx;
                for direction in 0..2 {
                    let mut current = [EpochRxSlot::default(), EpochRxSlot::default()];
                    for slot in rx[direction].iter().copied() {
                        if !slot.valid {
                            continue;
                        }
                        if slot.epoch == initial_epoch {
                            current[0] = slot;
                            for previous in previous_slots[direction].iter_mut() {
                                if previous.valid && previous.epoch == initial_epoch {
                                    previous.clear();
                                }
                            }
                            break;
                        }
                    }
                    rx[direction] = current;
                }
                sync_rx_grace.refresh(previous_slots, expires_at_ms);
                self.sync_rx_grace_expires_at_ms
                    .store(expires_at_ms, Ordering::Relaxed);
            } else {
                sync_rx_grace.clear();
                self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
                for dir in 0..2 {
                    rx[dir][0].clear();
                    rx[dir][1].clear();
                }
            }
        }

        self.key_cache
            .lock()
            .unwrap()
            .fill([EpochKeySlot::default(), EpochKeySlot::default()]);
        // A root-key sync starts a new authenticated epoch. Do not carry a
        // failure streak from the previous key into the new session state.
        self.decrypt_fail_count.store(0, Ordering::Release);
    }

    fn hkdf_traffic_key(&self, epoch: u32, dir: SecureDatagramDirection) -> [u8; 32] {
        self.hkdf_traffic_key_with_label(epoch, dir, b"et-traffic")
    }


    fn hkdf_traffic_key_with_label(
        &self,
        epoch: u32,
        dir: SecureDatagramDirection,
        label: &[u8],
    ) -> [u8; 32] {
        let root_key = self.root_key();
        let salt = [0u8; 32];
        let mut extract = HmacSha256::new_from_slice(&salt).unwrap();
        extract.update(&root_key);
        let prk = extract.finalize().into_bytes();

        let mut info = Vec::with_capacity(label.len() + 4 + 1);
        info.extend_from_slice(label);
        info.extend_from_slice(&epoch.to_be_bytes());
        info.push(dir.idx() as u8);

        let mut expand = HmacSha256::new_from_slice(&prk).unwrap();
        expand.update(&info);
        expand.update(&[1u8]);
        let okm = expand.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[..32]);
        key
    }

    fn get_or_create_encryptor(
        &self,
        epoch: u32,
        dir: SecureDatagramDirection,
        generation: u32,
        is_send: bool,
    ) -> Arc<dyn Encryptor> {
        let dir_idx = dir.idx();
        let mut guard = self.key_cache.lock().unwrap();
        for slot in guard[dir_idx].iter_mut() {
            if slot.valid && slot.epoch == epoch && slot.generation == generation {
                return slot.get_encryptor(is_send);
            }
        }

        let key = self.hkdf_traffic_key(epoch, dir);
        let mut key_128 = [0u8; 16];
        key_128.copy_from_slice(&key[..16]);

        let slot = EpochKeySlot {
            epoch,
            generation,
            valid: true,
            send_cipher: Some(create_secure_datagram_encryptor(
                &self.send_cipher_algorithm,
                key_128,
                key,
            )),
            recv_cipher: Some(create_secure_datagram_encryptor(
                &self.recv_cipher_algorithm,
                key_128,
                key,
            )),
        };
        let ret = slot.get_encryptor(is_send);

        if !guard[dir_idx][0].valid || guard[dir_idx][0].epoch == epoch {
            guard[dir_idx][0] = slot;
        } else {
            guard[dir_idx][1] = slot;
        }

        ret
    }


    fn maybe_rotate_epoch(&self, now_ms: u64, packet_count: u64) {
        let mut packets = self.send_packets_since_epoch.load(Ordering::Acquire);
        loop {
            let next_packets = packets.saturating_add(packet_count);
            match self.send_packets_since_epoch.compare_exchange_weak(
                packets,
                next_packets,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    packets = next_packets;
                    break;
                }
                Err(observed) => packets = observed,
            }
        }
        let started = self.send_epoch_started_ms.load(Ordering::Relaxed);
        if packets < Self::ROTATE_AFTER_PACKETS
            && now_ms.saturating_sub(started) < Self::ROTATE_AFTER_MS
        {
            return;
        }

        let _rotation_guard = self.rotation_lock.lock().unwrap();
        let packets = self.send_packets_since_epoch.load(Ordering::Relaxed);
        let started = self.send_epoch_started_ms.load(Ordering::Relaxed);
        if packets < Self::ROTATE_AFTER_PACKETS
            && now_ms.saturating_sub(started) < Self::ROTATE_AFTER_MS
        {
            return;
        }
        let cur = self.send_epoch.load(Ordering::Relaxed);
        let next = cur.wrapping_add(1);
        self.send_epoch.store(next, Ordering::Relaxed);
        self.send_epoch_started_ms.store(now_ms, Ordering::Relaxed);
        self.send_packets_since_epoch.store(0, Ordering::Relaxed);
    }

    fn reserve_nonce_range(
        &self,
        dir: SecureDatagramDirection,
        packet_count: usize,
        now_ms: u64,
    ) -> Result<(u32, u64), anyhow::Error> {
        let packet_count = u64::try_from(packet_count)
            .map_err(|_| anyhow!("secure datagram batch is too large"))?;
        if packet_count == 0 {
            return Ok((self.send_epoch.load(Ordering::Relaxed), 0));
        }
        self.maybe_rotate_epoch(now_ms, packet_count);
        let epoch = self.send_epoch.load(Ordering::Relaxed);
        let seq = loop {
            let current = self.send_seq[dir.idx()].load(Ordering::Relaxed);
            if current > u64::MAX.saturating_sub(packet_count) {
                return Err(anyhow!("secure datagram nonce sequence exhausted"));
            }
            if self.send_seq[dir.idx()]
                .compare_exchange_weak(
                    current,
                    current + packet_count,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break current;
            }
        };
        Ok((epoch, seq))
    }


    fn nonce(epoch: u32, seq: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&epoch.to_be_bytes());
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        nonce
    }

    fn next_nonce(
        &self,
        dir: SecureDatagramDirection,
        now_ms: u64,
    ) -> Result<(u32, u64, [u8; 12]), anyhow::Error> {
        let (epoch, seq) = self.reserve_nonce_range(dir, 1, now_ms)?;
        Ok((epoch, seq, Self::nonce(epoch, seq)))
    }

    fn parse_tail(payload: &[u8]) -> Option<[u8; 12]> {
        let tail = StandardAeadTail::ref_from_suffix(payload)?;
        Some(tail.nonce)
    }

    fn packet_aad(
        packet: &ZCPacket,
    ) -> Result<[u8; PEER_MANAGER_STABLE_AUTH_DATA_SIZE], anyhow::Error> {
        let header = packet
            .peer_manager_header()
            .ok_or_else(|| anyhow!("secure datagram packet has no peer header"))?;
        Ok(header.stable_auth_data())
    }

    fn epoch_in_slots(slots: &[EpochRxSlot; 2], epoch: u32) -> bool {
        slots[0].valid && slots[0].epoch == epoch || slots[1].valid && slots[1].epoch == epoch
    }

    fn sync_rx_grace_active(&self, now_ms: u64) -> bool {
        let expires_at_ms = self.sync_rx_grace_expires_at_ms.load(Ordering::Relaxed);
        if expires_at_ms == 0 {
            return false;
        }
        if now_ms < expires_at_ms {
            return true;
        }
        self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
        false
    }

    fn replay_state_snapshot(&self, now_ms: u64) -> ([[EpochRxSlot; 2]; 2], SyncRxGrace) {
        let rx = *self.rx_slots.lock().unwrap();
        let mut grace = *self.sync_rx_grace.lock().unwrap();
        if grace.valid {
            grace.maybe_expire(now_ms);
            if !grace.valid {
                self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
            }
        }
        (rx, grace)
    }




    fn precheck_replay_state(
        rx: &[[EpochRxSlot; 2]; 2],
        sync_rx_grace: Option<&SyncRxGrace>,
        send_epoch: u32,
        epoch: u32,
        seq: u64,
        dir_idx: usize,
    ) -> bool {
        if sync_rx_grace
            .as_ref()
            .is_some_and(|g| Self::epoch_in_slots(&g.slots[dir_idx], epoch))
        {
            for slot in sync_rx_grace.unwrap().slots[dir_idx].iter() {
                if slot.valid && slot.epoch == epoch {
                    return slot.window.can_accept(seq);
                }
            }
        }

        if !rx[dir_idx][0].valid {
            let baseline_epoch = send_epoch;
            return epoch <= baseline_epoch.saturating_add(Self::MAX_ACCEPTED_RX_EPOCH_AHEAD);
        }

        if epoch == rx[dir_idx][0].epoch {
            return rx[dir_idx][0].window.can_accept(seq);
        }

        if rx[dir_idx][1].valid && epoch == rx[dir_idx][1].epoch {
            return rx[dir_idx][1].window.can_accept(seq);
        }

        if epoch > rx[dir_idx][0].epoch {
            let mut baseline_epoch = send_epoch.max(rx[dir_idx][0].epoch);
            if rx[dir_idx][1].valid {
                baseline_epoch = baseline_epoch.max(rx[dir_idx][1].epoch);
            }
            return epoch <= baseline_epoch.saturating_add(Self::MAX_ACCEPTED_RX_EPOCH_AHEAD);
        }

        false
    }

    fn commit_replay_state(
        rx: &mut [[EpochRxSlot; 2]; 2],
        sync_rx_grace: &mut Option<SyncRxGrace>,
        send_epoch: u32,
        epoch: u32,
        seq: u64,
        dir_idx: usize,
        now_ms: u64,
    ) -> bool {
        if sync_rx_grace
            .as_ref()
            .is_some_and(|g| Self::epoch_in_slots(&g.slots[dir_idx], epoch))
        {
            let grace = sync_rx_grace
                .as_mut()
                .expect("grace state was checked before mutation");
            for slot in grace.slots[dir_idx].iter_mut() {
                if slot.valid && slot.epoch == epoch {
                    slot.last_rx_ms = now_ms;
                    return slot.window.accept(seq);
                }
            }
            return false;
        }

        if !rx[dir_idx][0].valid {
            let baseline_epoch = send_epoch;
            if epoch > baseline_epoch.saturating_add(Self::MAX_ACCEPTED_RX_EPOCH_AHEAD) {
                return false;
            }
            rx[dir_idx][0] = EpochRxSlot {
                epoch,
                window: ReplayWindow::default(),
                last_rx_ms: now_ms,
                valid: true,
            };
        }

        if epoch == rx[dir_idx][0].epoch {
            rx[dir_idx][0].last_rx_ms = now_ms;
            return rx[dir_idx][0].window.accept(seq);
        }
        if rx[dir_idx][1].valid && epoch == rx[dir_idx][1].epoch {
            rx[dir_idx][1].last_rx_ms = now_ms;
            return rx[dir_idx][1].window.accept(seq);
        }
        if epoch > rx[dir_idx][0].epoch {
            let mut baseline_epoch = send_epoch.max(rx[dir_idx][0].epoch);
            if rx[dir_idx][1].valid {
                baseline_epoch = baseline_epoch.max(rx[dir_idx][1].epoch);
            }
            if epoch > baseline_epoch.saturating_add(Self::MAX_ACCEPTED_RX_EPOCH_AHEAD) {
                return false;
            }
            rx[dir_idx][1] = rx[dir_idx][0];
            rx[dir_idx][0] = EpochRxSlot {
                epoch,
                window: ReplayWindow::default(),
                last_rx_ms: now_ms,
                valid: true,
            };
            return rx[dir_idx][0].window.accept(seq);
        }

        false
    }

    fn prune_key_cache(&self, rx: &[[EpochRxSlot; 2]; 2], sync_rx_grace: Option<&SyncRxGrace>) {
        let send_epoch = self.send_epoch.load(Ordering::Relaxed);
        let mut key_cache = self.key_cache.lock().unwrap();
        for d in 0..2 {
            for s in 0..2 {
                if !key_cache[d][s].valid {
                    continue;
                }
                let e = key_cache[d][s].epoch;
                let allowed = e == send_epoch
                    || rx[d][0].valid && rx[d][0].epoch == e
                    || rx[d][1].valid && rx[d][1].epoch == e
                    || sync_rx_grace.is_some_and(|g| Self::epoch_in_slots(&g.slots[d], e));
                if !allowed {
                    key_cache[d][s].valid = false;
                }
            }
        }
    }

    fn precheck_replay(
        &self,
        epoch: u32,
        seq: u64,
        dir: SecureDatagramDirection,
        now_ms: u64,
    ) -> bool {
        let dir_idx = dir.idx();
        let rx = self.rx_slots.lock().unwrap();
        let sync_rx_grace = if self.sync_rx_grace_active(now_ms) {
            let mut sync_rx_grace = self.sync_rx_grace.lock().unwrap();
            sync_rx_grace.maybe_expire(now_ms);
            if sync_rx_grace.valid {
                Some(sync_rx_grace)
            } else {
                self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
                None
            }
        } else {
            None
        };

        if sync_rx_grace
            .as_ref()
            .is_some_and(|g| Self::epoch_in_slots(&g.slots[dir_idx], epoch))
        {
            for slot in sync_rx_grace.as_ref().unwrap().slots[dir_idx].iter() {
                if slot.valid && slot.epoch == epoch {
                    return slot.window.can_accept(seq);
                }
            }
        }

        if !rx[dir_idx][0].valid {
            let send_epoch = self.send_epoch.load(Ordering::Relaxed);
            let baseline_epoch = send_epoch;
            return epoch <= baseline_epoch.saturating_add(Self::MAX_ACCEPTED_RX_EPOCH_AHEAD);
        }

        if rx[dir_idx][0].valid && epoch == rx[dir_idx][0].epoch {
            return rx[dir_idx][0].window.can_accept(seq);
        }

        if rx[dir_idx][1].valid && epoch == rx[dir_idx][1].epoch {
            return rx[dir_idx][1].window.can_accept(seq);
        }

        if rx[dir_idx][0].valid && epoch > rx[dir_idx][0].epoch {
            let mut baseline_epoch = self
                .send_epoch
                .load(Ordering::Relaxed);
            if rx[dir_idx][0].valid {
                baseline_epoch = baseline_epoch.max(rx[dir_idx][0].epoch);
            }
            if rx[dir_idx][1].valid {
                baseline_epoch = baseline_epoch.max(rx[dir_idx][1].epoch);
            }
            let max_allowed_epoch =
                baseline_epoch.saturating_add(Self::MAX_ACCEPTED_RX_EPOCH_AHEAD);
            if epoch > max_allowed_epoch {
                return false;
            }

            return true;
        }

        false
    }

    fn commit_replay(
        &self,
        epoch: u32,
        seq: u64,
        dir: SecureDatagramDirection,
        now_ms: u64,
    ) -> bool {
        let dir_idx = dir.idx();
        let mut rx = self.rx_slots.lock().unwrap();
        let mut sync_rx_grace = if self.sync_rx_grace_active(now_ms) {
            let mut sync_rx_grace = self.sync_rx_grace.lock().unwrap();
            sync_rx_grace.maybe_expire(now_ms);
            if sync_rx_grace.valid {
                Some(sync_rx_grace)
            } else {
                self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
                None
            }
        } else {
            None
        };

        let accepted = if sync_rx_grace
            .as_ref()
            .is_some_and(|g| Self::epoch_in_slots(&g.slots[dir_idx], epoch))
        {
            let mut accepted = false;
            for slot in sync_rx_grace.as_mut().unwrap().slots[dir_idx].iter_mut() {
                if slot.valid && slot.epoch == epoch {
                    slot.last_rx_ms = now_ms;
                    accepted = slot.window.accept(seq);
                    break;
                }
            }
            accepted
        } else {
            if !rx[dir_idx][0].valid {
                let send_epoch = self.send_epoch.load(Ordering::Relaxed);
                let baseline_epoch = send_epoch;
                if epoch > baseline_epoch.saturating_add(Self::MAX_ACCEPTED_RX_EPOCH_AHEAD) {
                    false
                } else {
                    rx[dir_idx][0] = EpochRxSlot {
                        epoch,
                        window: ReplayWindow::default(),
                        last_rx_ms: now_ms,
                        valid: true,
                    };
                    rx[dir_idx][0].window.accept(seq)
                }
            } else if epoch == rx[dir_idx][0].epoch {
                rx[dir_idx][0].last_rx_ms = now_ms;
                rx[dir_idx][0].window.accept(seq)
            } else if rx[dir_idx][1].valid && epoch == rx[dir_idx][1].epoch {
                rx[dir_idx][1].last_rx_ms = now_ms;
                rx[dir_idx][1].window.accept(seq)
            } else if rx[dir_idx][0].valid && epoch > rx[dir_idx][0].epoch {
                let mut baseline_epoch = self
                    .send_epoch
                    .load(Ordering::Relaxed);
                if rx[dir_idx][0].valid {
                    baseline_epoch = baseline_epoch.max(rx[dir_idx][0].epoch);
                }
                if rx[dir_idx][1].valid {
                    baseline_epoch = baseline_epoch.max(rx[dir_idx][1].epoch);
                }
                let max_allowed_epoch =
                    baseline_epoch.saturating_add(Self::MAX_ACCEPTED_RX_EPOCH_AHEAD);
                if epoch > max_allowed_epoch {
                    false
                } else {
                    rx[dir_idx][1] = rx[dir_idx][0];
                    rx[dir_idx][0] = EpochRxSlot {
                        epoch,
                        window: ReplayWindow::default(),
                        last_rx_ms: now_ms,
                        valid: true,
                    };
                    rx[dir_idx][0].window.accept(seq)
                }
            } else {
                false
            }
        };

        self.prune_key_cache(&rx, sync_rx_grace.as_deref());
        accepted
    }

    fn check_replay(
        &self,
        epoch: u32,
        seq: u64,
        dir: SecureDatagramDirection,
        now_ms: u64,
    ) -> bool {
        if self.precheck_replay(epoch, seq, dir, now_ms) {
            return self.commit_replay(epoch, seq, dir, now_ms);
        }

        false
    }





    pub fn encrypt_payload(
        &self,
        dir: SecureDatagramDirection,
        pkt: &mut ZCPacket,
    ) -> Result<(), anyhow::Error> {
        let _transition_guard = self.state_transition.read().unwrap();
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        let (epoch, _seq, nonce_bytes) = self.next_nonce(dir, now_ms())?;
        let aad = Self::packet_aad(pkt)?;
        let encryptor = self.get_or_create_encryptor(epoch, dir, self.session_generation(), true);
        if let Err(e) =
            encryptor.encrypt_with_nonce_and_aad(pkt, Some(nonce_bytes.as_slice()), &aad)
        {
            tracing::warn!(?e, "secure datagram session encrypt failed, invalidating");
            self.invalidate();
            return Err(e.into());
        }
        Ok(())
    }

    pub fn encrypt_payload_batch(
        &self,
        dir: SecureDatagramDirection,
        packets: &mut [ZCPacket],
    ) -> Result<(), anyhow::Error> {
        let _transition_guard = self.state_transition.read().unwrap();
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        if packets.is_empty() {
            return Ok(());
        }

        let now_ms = now_ms();
        let (epoch, start_seq) = self.reserve_nonce_range(dir, packets.len(), now_ms)?;
        let encryptor = self.get_or_create_encryptor(epoch, dir, self.session_generation(), true);
        for (offset, packet) in packets.iter_mut().enumerate() {
            let seq = start_seq
                .checked_add(offset as u64)
                .ok_or_else(|| anyhow!("secure datagram nonce sequence exhausted"))?;
            let nonce_bytes = Self::nonce(epoch, seq);
            let aad = Self::packet_aad(packet)?;
            if let Err(error) =
                encryptor.encrypt_with_nonce_and_aad(packet, Some(nonce_bytes.as_slice()), &aad)
            {
                tracing::warn!(?error, "secure datagram batch encrypt failed, invalidating");
                self.invalidate();
                return Err(error.into());
            }
        }
        Ok(())
    }



    pub fn decrypt_payload(
        &self,
        dir: SecureDatagramDirection,
        ciphertext_with_tail: &mut ZCPacket,
    ) -> Result<(), anyhow::Error> {
        let _transition_guard = self.state_transition.read().unwrap();
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        if !ciphertext_with_tail
            .peer_manager_header()
            .is_some_and(|header| header.is_encrypted())
        {
            return Err(anyhow!("secure datagram packet is not encrypted"));
        }
        let nonce_bytes =
            Self::parse_tail(ciphertext_with_tail.payload()).ok_or_else(|| anyhow!("no tail"))?;
        let aad = Self::packet_aad(ciphertext_with_tail)?;
        let epoch = u32::from_be_bytes(nonce_bytes[..4].try_into().unwrap());
        let seq = u64::from_be_bytes(nonce_bytes[4..].try_into().unwrap());

        let now_ms = now_ms();
        if !self.precheck_replay(epoch, seq, dir, now_ms) {
            return Err(anyhow!("replay rejected"));
        }

        let encryptor = self.get_or_create_encryptor(epoch, dir, self.session_generation(), false);
        if let Err(e) = encryptor.decrypt_with_aad(ciphertext_with_tail, &aad) {
            self.record_decrypt_failure();
            return Err(e.into());
        }

        if !self.commit_replay(epoch, seq, dir, now_ms) {
            return Err(anyhow!("replay rejected"));
        }

        self.record_authenticated_success();

        Ok(())
    }


    /// Decrypt one batch with one replay snapshot and one replay commit.
    ///
    /// Each output entry reports the result for the packet at the same index.
    /// A malformed, forged, or replayed packet does not discard valid peers.
    pub fn decrypt_payload_batch(
        &self,
        dir: SecureDatagramDirection,
        packets: &mut [ZCPacket],
    ) -> SmallVec<[Result<(), anyhow::Error>; 64]> {
        let _transition_guard = self.state_transition.read().unwrap();
        if !self.is_valid() {
            return packets
                .iter()
                .map(|_| Err(anyhow!("session invalidated")))
                .collect::<SmallVec<_>>();
        }
        if packets.is_empty() {
            return SmallVec::new();
        }

        let dir_idx = dir.idx();
        let mut nonces = SmallVec::<[Option<(u32, u64)>; 64]>::new();
        let mut aads = SmallVec::<[Option<[u8; PEER_MANAGER_STABLE_AUTH_DATA_SIZE]>; 64]>::new();
        let mut nonce_slots = [None::<((u32, u64), usize)>; 128];
        let mut duplicate = [false; 64];
        let mut outcomes = SmallVec::<[Option<Result<(), anyhow::Error>>; 64]>::new();
        outcomes.resize_with(packets.len(), || None);
        for (index, packet) in packets.iter().enumerate() {
            if !packet
                .peer_manager_header()
                .is_some_and(|header| header.is_encrypted())
            {
                outcomes[index] = Some(Err(anyhow!("secure datagram packet is not encrypted")));
                nonces.push(None);
                aads.push(None);
                continue;
            }
            let Some(nonce_bytes) = Self::parse_tail(packet.payload()) else {
                outcomes[index] = Some(Err(anyhow!("no tail")));
                nonces.push(None);
                aads.push(None);
                continue;
            };
            let aad = match Self::packet_aad(packet) {
                Ok(aad) => aad,
                Err(error) => {
                    outcomes[index] = Some(Err(error));
                    nonces.push(None);
                    aads.push(None);
                    continue;
                }
            };
            let epoch = u32::from_be_bytes(nonce_bytes[..4].try_into().unwrap());
            let seq = u64::from_be_bytes(nonce_bytes[4..].try_into().unwrap());
            let nonce = (epoch, seq);
            let mut slot = ((epoch as usize).wrapping_mul(0x9e37_79b1)
                ^ (seq as usize)
                ^ ((seq >> 32) as usize))
                & (nonce_slots.len() - 1);
            loop {
                match nonce_slots[slot] {
                    Some((stored, first)) if stored == nonce => {
                        duplicate[first] = true;
                        duplicate[index] = true;
                        break;
                    }
                    Some(_) => slot = (slot + 1) & (nonce_slots.len() - 1),
                    None => {
                        nonce_slots[slot] = Some((nonce, index));
                        break;
                    }
                }
            }
            nonces.push(Some(nonce));
            aads.push(Some(aad));
        }

        let now_ms = now_ms();
        let (rx_snapshot, grace_snapshot) = self.replay_state_snapshot(now_ms);
        let send_epoch = self.send_epoch.load(Ordering::Relaxed);
        let grace = grace_snapshot.valid.then_some(&grace_snapshot);
        let mut candidates = SmallVec::<[usize; 64]>::new();
        let mut saw_decrypt_failure = false;
        for (index, nonce) in nonces.iter().enumerate() {
            let Some((epoch, seq)) = nonce else {
                continue;
            };
            if duplicate[index] {
                outcomes[index] = Some(Err(anyhow!("duplicate nonce in secure datagram batch")));
                continue;
            }
            if !Self::precheck_replay_state(
                &rx_snapshot,
                grace,
                send_epoch,
                *epoch,
                *seq,
                dir_idx,
            ) {
                outcomes[index] = Some(Err(anyhow!("replay rejected")));
                continue;
            }
            candidates.push(index);
        }

        // Cache one decryptor per epoch. Most batches use one epoch.
        let mut decryptors = SmallVec::<[(u32, Arc<dyn Encryptor>); 2]>::new();
        for index in candidates.iter().copied() {
            let (epoch, _seq) = nonces[index].expect("candidate has a nonce");
            let aad = aads[index].as_ref().expect("candidate has AAD");
            let decryptor = if let Some((_, decryptor)) = decryptors
                .iter()
                .find(|(cached_epoch, _)| *cached_epoch == epoch)
            {
                decryptor.clone()
            } else {
                let decryptor =
                    self.get_or_create_encryptor(epoch, dir, self.session_generation(), false);
                decryptors.push((epoch, decryptor.clone()));
                decryptor
            };
            if let Err(error) = decryptor.decrypt_with_aad(&mut packets[index], aad) {
                saw_decrypt_failure = true;
                outcomes[index] = Some(Err(error.into()));
            } else {
                outcomes[index] = Some(Ok(()));
            }
        }

        // Recheck and commit in epoch/sequence order. This makes concurrent
        // batch decryptions deterministic and publishes replay state once.
        let mut commit_order = candidates
            .into_iter()
            .filter(|index| outcomes[*index].as_ref().is_some_and(Result::is_ok))
            .collect::<SmallVec<[usize; 64]>>();
        commit_order.sort_unstable_by_key(|index| {
            let (epoch, seq) = nonces[*index].expect("commit candidate has a nonce");
            (epoch, seq, *index)
        });
        let mut rx_guard = self.rx_slots.lock().unwrap();
        let mut grace_guard = self.sync_rx_grace.lock().unwrap();
        grace_guard.maybe_expire(now_ms);
        if !grace_guard.valid {
            self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
        }
        let mut rx_work = *rx_guard;
        let mut grace_work = grace_guard.valid.then_some(*grace_guard);
        for index in commit_order {
            let (epoch, seq) = nonces[index].expect("commit candidate has a nonce");
            if !Self::commit_replay_state(
                &mut rx_work,
                &mut grace_work,
                self.send_epoch.load(Ordering::Relaxed),
                epoch,
                seq,
                dir_idx,
                now_ms,
            ) {
                outcomes[index] = Some(Err(anyhow!("replay rejected")));
            }
        }
        *rx_guard = rx_work;
        *grace_guard = grace_work.unwrap_or_default();
        let grace_for_cache = grace_guard.valid.then_some(&*grace_guard);
        self.prune_key_cache(&rx_work, grace_for_cache);
        drop(grace_guard);
        drop(rx_guard);

        if outcomes
            .iter()
            .any(|outcome| outcome.as_ref().is_some_and(Result::is_ok))
        {
            self.record_authenticated_success();
        } else if saw_decrypt_failure {
            // Count one failure for this batch, not one failure per packet.
            self.record_decrypt_failure();
        }
        outcomes
            .into_iter()
            .map(|outcome| {
                outcome.unwrap_or_else(|| Err(anyhow!("secure datagram packet rejected")))
            })
            .collect::<SmallVec<_>>()
    }

    #[cfg(test)]
    fn check_replay_for_test(
        &self,
        epoch: u32,
        seq: u64,
        dir: SecureDatagramDirection,
        now_ms: u64,
    ) -> bool {
        self.check_replay(epoch, seq, dir, now_ms)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_the_root_key() {
        let root_key = [0xa5; 32];
        let session = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let output = format!("{session:?}");
        assert!(!output.contains("165"));
        assert!(output.contains("root_key: <redacted>"));
    }
    use crate::tunnel::packet_def::PacketType;

    fn encrypted_packet_for_aad() -> (SecureDatagramSession, ZCPacket) {
        let root_key = SecureDatagramSession::new_root_key();
        let sender = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let mut packet = ZCPacket::new_with_payload(b"authenticated header");
        packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut packet)
            .unwrap();
        (receiver, packet)
    }

    #[test]
    fn secure_datagram_supports_asymmetric_algorithms() {
        let root_key = SecureDatagramSession::new_root_key();
        let generation = 1u32;
        let initial_epoch = 0u32;

        let ab = SecureDatagramSession::new(
            root_key,
            generation,
            initial_epoch,
            "aes-256-gcm".to_string(),
            "chacha20-poly1305".to_string(),
        );
        let ba = SecureDatagramSession::new(
            root_key,
            generation,
            initial_epoch,
            "chacha20-poly1305".to_string(),
            "aes-256-gcm".to_string(),
        );

        let plaintext1 = b"hello from a";
        let mut pkt1 = ZCPacket::new_with_payload(plaintext1);
        pkt1.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        ab.encrypt_payload(SecureDatagramDirection::AToB, &mut pkt1)
            .unwrap();
        ba.decrypt_payload(SecureDatagramDirection::AToB, &mut pkt1)
            .unwrap();
        assert_eq!(pkt1.payload(), plaintext1);

        let plaintext2 = b"hello from b";
        let mut pkt2 = ZCPacket::new_with_payload(plaintext2);
        pkt2.fill_peer_manager_hdr(20, 10, PacketType::Data as u8);
        ba.encrypt_payload(SecureDatagramDirection::BToA, &mut pkt2)
            .unwrap();
        ab.decrypt_payload(SecureDatagramDirection::BToA, &mut pkt2)
            .unwrap();
        assert_eq!(pkt2.payload(), plaintext2);
    }





    #[test]
    fn batch_decrypt_reports_individual_forgery_without_discarding_valid_packets() {
        let root_key = SecureDatagramSession::new_root_key();
        let sender = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let mut packets = [
            ZCPacket::new_with_payload(b"valid-0"),
            ZCPacket::new_with_payload(b"forged"),
            ZCPacket::new_with_payload(b"valid-2"),
        ];
        for packet in &mut packets {
            packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        }
        sender
            .encrypt_payload_batch(SecureDatagramDirection::AToB, &mut packets)
            .unwrap();
        packets[1].mut_payload()[0] ^= 1;

        let outcomes = receiver.decrypt_payload_batch(SecureDatagramDirection::AToB, &mut packets);
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes[0].is_ok());
        assert!(outcomes[1].is_err());
        assert!(outcomes[2].is_ok());
        assert_eq!(packets[0].payload(), b"valid-0");
        assert_eq!(packets[2].payload(), b"valid-2");
        assert!(
            receiver
                .decrypt_payload(SecureDatagramDirection::AToB, &mut packets[0])
                .is_err()
        );
    }

    #[test]
    fn batch_decrypt_rejects_long_plaintext_before_crypto() {
        let receiver = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let mut plaintext = ZCPacket::new_with_payload(&[0x5a; 4096]);
        plaintext.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);

        let outcomes = receiver.decrypt_payload_batch(
            SecureDatagramDirection::AToB,
            std::slice::from_mut(&mut plaintext),
        );
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].is_err());
        assert!(receiver.is_valid());
        assert_eq!(plaintext.payload(), &[0x5a; 4096]);
    }

    #[test]
    fn batch_decrypt_keeps_authenticated_packet_next_to_plaintext() {
        let root_key = SecureDatagramSession::new_root_key();
        let sender = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let mut encrypted = ZCPacket::new_with_payload(b"authenticated");
        encrypted.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut encrypted)
            .unwrap();
        let mut plaintext = ZCPacket::new_with_payload(&[0x33; 4096]);
        plaintext.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);

        let mut packets = [encrypted, plaintext];
        let outcomes = receiver.decrypt_payload_batch(SecureDatagramDirection::AToB, &mut packets);
        assert!(outcomes[0].is_ok());
        assert!(outcomes[1].is_err());
        assert_eq!(packets[0].payload(), b"authenticated");
        assert_eq!(packets[1].payload(), &[0x33; 4096]);
        assert!(receiver.is_valid());
    }

    #[test]
    fn scalar_decrypt_failure_streak_saturates_without_invalidation() {
        let root_key = SecureDatagramSession::new_root_key();
        let sender = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        for _ in 0..SecureDatagramSession::DECRYPT_FAIL_THRESHOLD {
            let mut packet = ZCPacket::new_with_payload(b"forged");
            packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
            sender
                .encrypt_payload(SecureDatagramDirection::AToB, &mut packet)
                .unwrap();
            packet.mut_payload()[0] ^= 1;
            assert!(
                receiver
                    .decrypt_payload(SecureDatagramDirection::AToB, &mut packet)
                    .is_err()
            );
            assert!(receiver.is_valid());
        }
        assert_eq!(
            receiver.decrypt_fail_count.load(Ordering::Relaxed),
            SecureDatagramSession::DECRYPT_FAIL_THRESHOLD
        );
    }

    #[test]
    fn authenticated_sync_resets_decrypt_failure_streak() {
        let old_root_key = SecureDatagramSession::new_root_key();
        let sender = SecureDatagramSession::new(
            old_root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            old_root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        for _ in 0..(SecureDatagramSession::DECRYPT_FAIL_THRESHOLD - 1) {
            let mut packet = ZCPacket::new_with_payload(b"forged-before-sync");
            packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
            sender
                .encrypt_payload(SecureDatagramDirection::AToB, &mut packet)
                .unwrap();
            packet.mut_payload()[0] ^= 1;
            assert!(
                receiver
                    .decrypt_payload(SecureDatagramDirection::AToB, &mut packet)
                    .is_err()
            );
        }
        assert!(receiver.is_valid());
        assert_eq!(
            receiver.decrypt_fail_count.load(Ordering::Relaxed),
            SecureDatagramSession::DECRYPT_FAIL_THRESHOLD - 1
        );

        let new_root_key = SecureDatagramSession::new_root_key();
        receiver.sync_root_key(new_root_key, 2, 1, false);
        assert_eq!(receiver.decrypt_fail_count.load(Ordering::Relaxed), 0);

        let sender_after_sync = SecureDatagramSession::new(
            new_root_key,
            2,
            1,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let mut packet = ZCPacket::new_with_payload(b"forged-after-sync");
        packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender_after_sync
            .encrypt_payload(SecureDatagramDirection::AToB, &mut packet)
            .unwrap();
        packet.mut_payload()[0] ^= 1;
        assert!(
            receiver
                .decrypt_payload(SecureDatagramDirection::AToB, &mut packet)
                .is_err()
        );
        assert!(receiver.is_valid());
        assert_eq!(receiver.decrypt_fail_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn batch_decrypt_counts_one_failure_for_the_batch_and_resets_on_success() {
        let root_key = SecureDatagramSession::new_root_key();
        let sender = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let mut forged_batch = Vec::new();
        for _ in 0..SecureDatagramSession::DECRYPT_FAIL_THRESHOLD {
            let mut packet = ZCPacket::new_with_payload(b"forged");
            packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
            sender
                .encrypt_payload(SecureDatagramDirection::AToB, &mut packet)
                .unwrap();
            packet.mut_payload()[0] ^= 1;
            forged_batch.push(packet);
        }
        let outcomes = receiver
            .decrypt_payload_batch(SecureDatagramDirection::AToB, forged_batch.as_mut_slice());
        assert!(outcomes.iter().all(Result::is_err));
        assert!(receiver.is_valid());
        assert_eq!(
            receiver.decrypt_fail_count.load(Ordering::Relaxed),
            1,
            "a batch contributes one failure regardless of packet count"
        );

        let mut valid = ZCPacket::new_with_payload(b"valid");
        valid.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut valid)
            .unwrap();
        let mut mixed = [valid, forged_batch.remove(0)];
        // The second packet is still forged, while the first packet proves the
        // session and clears the old failure streak.
        let outcomes = receiver.decrypt_payload_batch(SecureDatagramDirection::AToB, &mut mixed);
        assert!(outcomes[0].is_ok());
        assert!(outcomes[1].is_err());
        assert_eq!(receiver.decrypt_fail_count.load(Ordering::Relaxed), 0);
        assert!(receiver.is_valid());

        for _ in 0..SecureDatagramSession::DECRYPT_FAIL_THRESHOLD {
            let mut packet = ZCPacket::new_with_payload(b"forged-again");
            packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
            sender
                .encrypt_payload(SecureDatagramDirection::AToB, &mut packet)
                .unwrap();
            packet.mut_payload()[0] ^= 1;
            let outcomes = receiver.decrypt_payload_batch(
                SecureDatagramDirection::AToB,
                std::slice::from_mut(&mut packet),
            );
            assert!(outcomes[0].is_err());
            assert!(receiver.is_valid());
        }
        assert_eq!(
            receiver.decrypt_fail_count.load(Ordering::Relaxed),
            SecureDatagramSession::DECRYPT_FAIL_THRESHOLD
        );
    }

    #[test]
    fn batch_decrypt_rejects_reserved_flag_tampering_without_discarding_valid_packets() {
        let root_key = SecureDatagramSession::new_root_key();
        let sender = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let mut packets = [
            ZCPacket::new_with_payload(b"valid-0"),
            ZCPacket::new_with_payload(b"forged-flag"),
            ZCPacket::new_with_payload(b"valid-2"),
        ];
        for packet in &mut packets {
            packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        }
        sender
            .encrypt_payload_batch(SecureDatagramDirection::AToB, &mut packets)
            .unwrap();
        packets[1].mut_peer_manager_header().unwrap().flags ^= 0x80;

        let outcomes = receiver.decrypt_payload_batch(SecureDatagramDirection::AToB, &mut packets);
        assert!(outcomes[0].is_ok());
        assert!(outcomes[1].is_err());
        assert!(outcomes[2].is_ok());
        assert_eq!(packets[0].payload(), b"valid-0");
        assert_eq!(packets[2].payload(), b"valid-2");
    }

    #[test]
    fn batch_decrypt_marks_both_duplicate_nonce_packets() {
        let root_key = SecureDatagramSession::new_root_key();
        let sender = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let mut packet = ZCPacket::new_with_payload(b"duplicate");
        packet.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut packet)
            .unwrap();
        let mut packets = [packet.clone(), packet];
        let outcomes = receiver.decrypt_payload_batch(SecureDatagramDirection::AToB, &mut packets);
        assert!(outcomes.iter().all(Result::is_err));
        assert!(
            receiver
                .decrypt_payload(SecureDatagramDirection::AToB, &mut packets[0])
                .is_ok()
        );
    }

    #[test]
    fn concurrent_nonce_ranges_advance_one_epoch_and_do_not_overlap() {
        let session = Arc::new(SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        ));
        session.send_packets_since_epoch.store(
            SecureDatagramSession::ROTATE_AFTER_PACKETS - 1,
            Ordering::Relaxed,
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let session = session.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                session
                    .reserve_nonce_range(SecureDatagramDirection::AToB, 1, now_ms())
                    .unwrap()
            }));
        }
        let ranges = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(session.send_epoch.load(Ordering::Relaxed), 1);
        assert_ne!(ranges[0], ranges[1]);
    }




    #[test]
    fn first_standard_packet_rejects_far_future_epochs() {
        let root_key = SecureDatagramSession::new_root_key();
        let far_future_sender = SecureDatagramSession::new(
            root_key,
            1,
            SecureDatagramSession::MAX_ACCEPTED_RX_EPOCH_AHEAD + 1,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let mut standard = ZCPacket::new_with_payload(b"far-future-standard");
        standard.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        far_future_sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut standard)
            .unwrap();
        assert!(
            receiver
                .decrypt_payload(SecureDatagramDirection::AToB, &mut standard)
                .is_err()
        );

        assert!(receiver.is_valid());
        assert_eq!(receiver.decrypt_fail_count.load(Ordering::Relaxed), 0);
    }



    #[test]
    fn scalar_decrypt_rejects_stable_header_tampering() {
        let mut mutations: Vec<Box<dyn Fn(&mut ZCPacket)>> = vec![
            Box::new(|packet| {
                packet
                    .mut_peer_manager_header()
                    .unwrap()
                    .from_peer_id
                    .set(11)
            }),
            Box::new(|packet| packet.mut_peer_manager_header().unwrap().to_peer_id.set(21)),
            Box::new(|packet| {
                packet.mut_peer_manager_header().unwrap().packet_type = PacketType::Ethernet as u8
            }),
            Box::new(|packet| {
                packet
                    .mut_peer_manager_header()
                    .unwrap()
                    .set_exit_node(true);
            }),
            Box::new(|packet| {
                packet.mut_peer_manager_header().unwrap().set_no_proxy(true);
            }),
            Box::new(|packet| {
                packet
                    .mut_peer_manager_header()
                    .unwrap()
                    .set_compressed(true);
            }),
            Box::new(|packet| {
                packet
                    .mut_peer_manager_header()
                    .unwrap()
                    .set_not_send_to_tun(true);
            }),
            Box::new(|packet| {
                packet.mut_peer_manager_header().unwrap().flags ^= 0x80;
            }),
            Box::new(|packet| {
                packet
                    .mut_peer_manager_header()
                    .unwrap()
                    .set_critical_l2_control(true);
            }),
            Box::new(|packet| {
                packet.mut_peer_manager_header().unwrap().set_flow_shard(7);
            }),
            Box::new(|packet| {
                packet.mut_peer_manager_header().unwrap().len.set(1);
            }),
        ];

        for mutate in mutations.drain(..) {
            let (receiver, mut packet) = encrypted_packet_for_aad();
            mutate(&mut packet);
            assert!(
                receiver
                    .decrypt_payload(SecureDatagramDirection::AToB, &mut packet)
                    .is_err()
            );
        }
    }

    #[test]
    fn scalar_decrypt_allows_forward_and_route_preference_updates() {
        for mutate in [
            Box::new(|packet: &mut ZCPacket| {
                packet.mut_peer_manager_header().unwrap().forward_counter += 1;
            }) as Box<dyn Fn(&mut ZCPacket)>,
            Box::new(|packet: &mut ZCPacket| {
                packet
                    .mut_peer_manager_header()
                    .unwrap()
                    .set_latency_first(true);
            }),
            Box::new(|packet: &mut ZCPacket| {
                packet
                    .mut_peer_manager_header()
                    .unwrap()
                    .set_speed_first(true);
            }),
        ] {
            let (receiver, mut packet) = encrypted_packet_for_aad();
            mutate(&mut packet);
            assert!(
                receiver
                    .decrypt_payload(SecureDatagramDirection::AToB, &mut packet)
                    .is_ok()
            );
        }
    }

    #[test]
    fn replay_rejects_far_future_epoch_without_poisoning_window() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let now = now_ms();

        assert!(s.check_replay_for_test(0, 1, SecureDatagramDirection::AToB, now));
        assert!(s.check_replay_for_test(0, 2, SecureDatagramDirection::AToB, now));

        assert!(!s.check_replay_for_test(1000, 1, SecureDatagramDirection::AToB, now));

        assert!(s.check_replay_for_test(1, 1, SecureDatagramDirection::AToB, now + 1));
        assert!(s.check_replay_for_test(1, 2, SecureDatagramDirection::AToB, now + 2));
    }

    #[test]
    fn replay_window_survives_idle_time() {
        let session = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let now = now_ms();

        assert!(session.check_replay_for_test(0, 7, SecureDatagramDirection::AToB, now));
        assert!(
            !session.check_replay_for_test(0, 7, SecureDatagramDirection::AToB, now + 120_000,)
        );
    }

    #[test]
    fn failed_decrypt_does_not_poison_replay_window() {
        let root_key = SecureDatagramSession::new_root_key();
        let sender = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );
        let receiver = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let mut pkt0 = ZCPacket::new_with_payload(b"pkt0");
        pkt0.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut pkt0)
            .unwrap();
        receiver
            .decrypt_payload(SecureDatagramDirection::AToB, &mut pkt0)
            .unwrap();

        let mut forged = ZCPacket::new_with_payload(b"forged");
        forged.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut forged)
            .unwrap();

        let mut poisoned_nonce = [0u8; StandardAeadTail::NONCE_SIZE];
        poisoned_nonce[..4].copy_from_slice(&0u32.to_be_bytes());
        poisoned_nonce[4..].copy_from_slice(&500u64.to_be_bytes());

        let payload = forged.mut_payload();
        let nonce_offset = payload.len() - StandardAeadTail::NONCE_SIZE;
        payload[nonce_offset..].copy_from_slice(&poisoned_nonce);

        assert!(
            receiver
                .decrypt_payload(SecureDatagramDirection::AToB, &mut forged)
                .is_err()
        );

        let plaintext = b"pkt2";
        let mut pkt2 = ZCPacket::new_with_payload(plaintext);
        pkt2.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
        sender
            .encrypt_payload(SecureDatagramDirection::AToB, &mut pkt2)
            .unwrap();
        receiver
            .decrypt_payload(SecureDatagramDirection::AToB, &mut pkt2)
            .unwrap();
        assert_eq!(pkt2.payload(), plaintext);
    }

    #[test]
    fn replay_window_shift_preserves_bits() {
        let mut w = ReplayWindow::default();
        for i in 0..10u64 {
            assert!(w.accept(i), "seq {i} should be accepted");
        }
        assert_eq!(w.max_sequence(), 9);

        for i in 0..10u64 {
            assert!(!w.accept(i), "seq {i} should be rejected as replay");
        }

        assert!(w.accept(10));
    }

    #[test]
    fn replay_window_out_of_order_within_window() {
        let mut w = ReplayWindow::default();
        for i in (0..=20u64).step_by(2) {
            assert!(w.accept(i), "seq {i} should be accepted");
        }
        for i in (1..=19u64).step_by(2) {
            assert!(w.accept(i), "seq {i} should be accepted (out of order)");
        }
        for i in 0..=20u64 {
            assert!(!w.accept(i), "seq {i} should be rejected as replay");
        }
    }

    #[test]
    fn sync_root_key_allows_any_epoch_from_remote() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let root_key = s.root_key();
        let now = now_ms();
        assert!(s.check_replay_for_test(0, 0, SecureDatagramDirection::AToB, now));
        assert!(s.check_replay_for_test(0, 1, SecureDatagramDirection::AToB, now));

        s.sync_root_key(root_key, 2, 2, true);

        assert!(s.check_replay_for_test(0, 10, SecureDatagramDirection::AToB, now + 1));
    }

    #[test]
    fn sync_root_key_keeps_previous_epochs_during_grace_window() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let root_key = s.root_key();
        let now = now_ms();
        assert!(s.check_replay_for_test(0, 0, SecureDatagramDirection::AToB, now));
        assert!(s.check_replay_for_test(1, 0, SecureDatagramDirection::AToB, now + 1));

        s.sync_root_key(root_key, 2, 2, true);

        assert!(s.check_replay_for_test(2, 0, SecureDatagramDirection::AToB, now + 2));
        assert!(s.check_replay_for_test(1, 1, SecureDatagramDirection::AToB, now + 3));
        assert!(s.check_replay_for_test(0, 1, SecureDatagramDirection::AToB, now + 4));
    }

    #[test]
    fn sync_keeps_target_epoch_replay_state_after_grace() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let root_key = s.root_key();
        let now = now_ms();
        assert!(s.check_replay_for_test(2, 0, SecureDatagramDirection::AToB, now));

        s.sync_root_key(root_key, 2, 2, true);

        assert!(!s.check_replay_for_test(2, 0, SecureDatagramDirection::AToB, now + 1));
        assert!(!s.check_replay_for_test(
            2,
            0,
            SecureDatagramDirection::AToB,
            now + SecureDatagramSession::SYNC_RX_GRACE_AFTER_MS + 1
        ));
    }

    #[test]
    fn sync_root_key_expires_previous_epochs_after_grace_window() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let root_key = s.root_key();
        let now = now_ms();
        assert!(s.check_replay_for_test(0, 0, SecureDatagramDirection::AToB, now));
        assert!(s.check_replay_for_test(1, 0, SecureDatagramDirection::AToB, now + 1));

        s.sync_root_key(root_key, 2, 2, true);
        assert!(s.check_replay_for_test(2, 0, SecureDatagramDirection::AToB, now + 2));

        assert!(!s.check_replay_for_test(
            0,
            1,
            SecureDatagramDirection::AToB,
            now + SecureDatagramSession::SYNC_RX_GRACE_AFTER_MS + 3
        ));
    }

    #[test]
    fn sync_root_key_does_not_preserve_previous_epochs_when_root_key_changes() {
        let s = SecureDatagramSession::new(
            SecureDatagramSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
        );

        let now = now_ms();
        assert!(s.check_replay_for_test(0, 0, SecureDatagramDirection::AToB, now));
        assert!(s.check_replay_for_test(1, 0, SecureDatagramDirection::AToB, now + 1));

        s.sync_root_key(SecureDatagramSession::new_root_key(), 2, 2, true);
        assert!(s.check_replay_for_test(2, 0, SecureDatagramDirection::AToB, now + 2));
        assert!(!s.check_replay_for_test(1, 1, SecureDatagramDirection::AToB, now + 3));
    }
}
