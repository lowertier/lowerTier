use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};
use std::time::Duration;

use anyhow::anyhow;
use crossbeam::atomic::AtomicCell;
use dashmap::{DashMap, mapref::entry::Entry};
use quanta::Instant;
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::secure_datagram::{SecureDatagramDirection, SecureDatagramSession};
use crate::{
    common::{PeerId, shrink_dashmap, verify_slices_are_equal},
    tunnel::packet_def::ZCPacket,
};

const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum compatibility value for callers that still pass a recovery window.
/// The store does not roll back an ambiguous transition when this window ends.
pub const INITIATOR_RECOVERY_LIFETIME: Duration = Duration::from_secs(120);
const MAX_IN_DOUBT_RESERVATIONS: usize = 256;
const MAX_COMMITTED_TRANSITIONS_PER_SESSION: usize = 8;
const MAX_RESPONDER_RECOVERY_RECORDS: usize = 256;
const MAX_RESPONDER_RECOVERIES_PER_PRINCIPAL: usize = 2;
const MAX_INITIATOR_RECEIPT_RECORDS: usize = 256;

static IN_DOUBT_RESERVATION_COUNT: AtomicUsize = AtomicUsize::new(0);
static RESPONDER_RECOVERY_RECORD_COUNT: AtomicUsize = AtomicUsize::new(0);
static INITIATOR_RECEIPT_RECORD_COUNT: AtomicUsize = AtomicUsize::new(0);

struct QuotaPermit {
    counter: &'static AtomicUsize,
}

impl Drop for QuotaPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct UpsertResponderSessionReturn {
    pub session: Arc<PeerSession>,
    pub action: PeerSessionAction,
    pub session_generation: u32,
    pub root_key: Option<[u8; 32]>,
    pub initial_epoch: u32,
    pub transition_revision: Option<u64>,
    pub transition_id: [u8; 16],
    /// Previous responder proof that must be authenticated before commit.
    pub proof_dependency: Option<[u8; 16]>,
    proof_cleared: AtomicBool,
    committed: AtomicBool,
    proof_backup: Mutex<Option<ResponderRecoveryBackup>>,
    pub(crate) prepared_store: PeerSessionStore,
    pub(crate) prepared_key: SessionKey,
}

impl UpsertResponderSessionReturn {
    pub fn for_recovery(
        session: Arc<PeerSession>,
        action: PeerSessionAction,
        session_generation: u32,
        root_key: [u8; 32],
        initial_epoch: u32,
        transition_id: [u8; 16],
        transition_revision: Option<u64>,
        prepared_store: PeerSessionStore,
        prepared_key: SessionKey,
    ) -> Self {
        Self {
            session,
            action,
            session_generation,
            root_key: Some(root_key),
            initial_epoch,
            transition_revision,
            transition_id,
            proof_dependency: None,
            proof_cleared: AtomicBool::new(false),
            committed: AtomicBool::new(false),
            proof_backup: Mutex::new(None),
            prepared_store,
            prepared_key,
        }
    }

    pub fn transition_token(&self) -> u64 {
        match self.action {
            PeerSessionAction::Create => self.session.transition_revision(),
            PeerSessionAction::Sync => self
                .transition_revision
                .expect("SYNC reservations always have a transition revision"),
            PeerSessionAction::Join => self.session.transition_revision(),
        }
    }

    pub fn transition_id(&self) -> [u8; 16] {
        self.transition_id
    }

    pub fn cancel(&self) {
        self.prepared_store.cancel_prepared_session(
            &self.prepared_key,
            &self.session,
            self.action,
            self.transition_revision,
            self.initial_epoch,
        );
    }

    fn restore_uncommitted_proof(&self) {
        if self.proof_dependency.is_some()
            && self.proof_cleared.load(Ordering::Acquire)
            && !self.committed.load(Ordering::Acquire)
        {
            self.prepared_store.restore_responder_recovery(self);
        }
    }

    pub fn proof_dependency(&self) -> Option<[u8; 16]> {
        self.proof_dependency
    }

    pub fn proof_dependency_cleared(&self) -> bool {
        self.proof_cleared.load(Ordering::Acquire)
    }

    /// Clear the previous proof after authenticated peer confirmation.
    pub fn authenticate_recovery(&self) -> Result<(), anyhow::Error> {
        let Some(transition_id) = self.proof_dependency else {
            return Ok(());
        };
        self.prepared_store
            .authenticate_prepared_responder_transition(&self.prepared_key, self, transition_id)
    }
}

impl Drop for UpsertResponderSessionReturn {
    fn drop(&mut self) {
        self.restore_uncommitted_proof();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeerSessionAction {
    Join,
    Sync,
    Create,
}

/// Exact identity for a hidden initiator transition.
///
/// The root key digest only matches the stored reservation. It never supplies
/// a root key for a new session or a synchronization operation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InitiatorTransitionIdentity {
    pub session_key: SessionKey,
    pub session_metadata_id: uuid::Uuid,
    pub action: PeerSessionAction,
    pub session_generation: u32,
    pub initial_epoch: u32,
    pub transition_id: [u8; 16],
    /// Local compare-and-swap revision. This value is never sent on the wire.
    pub transition_revision: u64,
    pub root_key_digest: [u8; 32],
}

impl InitiatorTransitionIdentity {
    pub fn new(
        session_key: SessionKey,
        session_metadata_id: uuid::Uuid,
        action: PeerSessionAction,
        session_generation: u32,
        initial_epoch: u32,
        transition_id: [u8; 16],
        root_key_digest: [u8; 32],
    ) -> Self {
        Self {
            session_key,
            session_metadata_id,
            action,
            session_generation,
            initial_epoch,
            transition_id,
            transition_revision: 0,
            root_key_digest,
        }
    }

    pub fn digest_root_key(root_key: &[u8; 32]) -> [u8; 32] {
        Sha256::digest(root_key).into()
    }

    pub fn matches_authenticated_fields(&self, other: &Self) -> bool {
        self.session_key == other.session_key
            && self.session_metadata_id == other.session_metadata_id
            && self.action == other.action
            && self.session_generation == other.session_generation
            && self.initial_epoch == other.initial_epoch
            && verify_slices_are_equal(&self.transition_id, &other.transition_id).is_ok()
            && verify_slices_are_equal(&self.root_key_digest, &other.root_key_digest).is_ok()
    }
}

#[derive(Clone)]
pub struct ResponderTransitionRecovery {
    pub session: Arc<PeerSession>,
    pub action: PeerSessionAction,
    pub session_generation: u32,
    pub root_key: [u8; 32],
    pub initial_epoch: u32,
    pub transition_id: [u8; 16],
    pub transition_revision: u64,
}

struct RedactedSecret;

impl std::fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::fmt::Debug for ResponderTransitionRecovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponderTransitionRecovery")
            .field("session", &self.session)
            .field("action", &self.action)
            .field("session_generation", &self.session_generation)
            .field("root_key", &RedactedSecret)
            .field("initial_epoch", &self.initial_epoch)
            .field("transition_id", &self.transition_id)
            .field("transition_revision", &self.transition_revision)
            .finish()
    }
}

const RESERVATION_PENDING: u8 = 0;
const RESERVATION_COMMITTED: u8 = 1;
const RESERVATION_CANCELED: u8 = 2;
const RESERVATION_SUSPENDED: u8 = 3;

fn try_reserve_global(counter: &AtomicUsize, limit: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn new_transition_id() -> [u8; 16] {
    loop {
        let mut id = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        if id != [0; 16] {
            return id;
        }
    }
}

/// An initiator session transition that is not visible in the session store.
///
/// Create transitions reserve a new session entry. Sync transitions reserve an
/// epoch on the existing session, but do not change its traffic keys until
/// commit. Join transitions validate the current session and hold its pointer.
pub struct InitiatorSessionReservation {
    store: PeerSessionStore,
    key: SessionKey,
    session: Arc<PeerSession>,
    action: PeerSessionAction,
    session_generation: u32,
    root_key: [u8; 32],
    initial_epoch: u32,
    transition_revision: u64,
    transition_id: [u8; 16],
    send_algorithm: String,
    recv_algorithm: String,
    peer_static_pubkey: Option<[u8; 32]>,
    recovery_quota: Mutex<Option<QuotaPermit>>,
    state: AtomicU8,
}

impl std::fmt::Debug for InitiatorSessionReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorSessionReservation")
            .field("key", &self.key)
            .field("action", &self.action)
            .field("session_generation", &self.session_generation)
            .field("initial_epoch", &self.initial_epoch)
            .field("transition_revision", &self.transition_revision)
            .finish()
    }
}

impl InitiatorSessionReservation {
    pub fn action(&self) -> PeerSessionAction {
        self.action
    }

    pub fn session(&self) -> Arc<PeerSession> {
        self.session.clone()
    }

    pub fn session_generation(&self) -> u32 {
        self.session_generation
    }

    pub fn root_key(&self) -> [u8; 32] {
        self.root_key
    }

    pub fn initial_epoch(&self) -> u32 {
        self.initial_epoch
    }

    /// Return the local transition token for confirmation and timeout checks.
    pub fn transition_revision(&self) -> u64 {
        self.transition_revision
    }

    pub fn transition_id(&self) -> [u8; 16] {
        self.transition_id
    }

    pub fn bind_transition_id(&mut self, transition_id: [u8; 16]) -> Result<(), anyhow::Error> {
        if transition_id == [0; 16] {
            return Err(anyhow!("session transition id must not be zero"));
        }
        if self.transition_id != [0; 16] && self.transition_id != transition_id {
            return Err(anyhow!("session transition id changed"));
        }
        self.transition_id = transition_id;
        Ok(())
    }

    pub fn verify_transition_revision(&self, expected: u64) -> Result<(), anyhow::Error> {
        if self.transition_revision != expected {
            return Err(anyhow!("session transition revision mismatch"));
        }
        Ok(())
    }

    pub fn transition_identity(&self) -> InitiatorTransitionIdentity {
        self.transition_identity_with_session_metadata(self.session.metadata_session_id())
    }

    pub fn transition_identity_with_session_metadata(
        &self,
        session_metadata_id: uuid::Uuid,
    ) -> InitiatorTransitionIdentity {
        let mut identity = InitiatorTransitionIdentity::new(
            self.key.clone(),
            session_metadata_id,
            self.action,
            self.session_generation,
            self.initial_epoch,
            self.transition_id,
            InitiatorTransitionIdentity::digest_root_key(&self.root_key),
        );
        identity.transition_revision = self.transition_revision;
        identity
    }

    fn matches_transition_identity_fields(&self, identity: &InitiatorTransitionIdentity) -> bool {
        identity.session_key == self.key
            && identity.action == self.action
            && identity.session_generation == self.session_generation
            && identity.initial_epoch == self.initial_epoch
            && identity.transition_id == self.transition_id
            && (identity.transition_revision == 0
                || identity.transition_revision == self.transition_revision)
            && identity.root_key_digest
                == InitiatorTransitionIdentity::digest_root_key(&self.root_key)
    }

    fn release_recovery_quota(&self) {
        self.recovery_quota.lock().unwrap().take();
    }

    fn suspend_with_identity(
        mut self,
        lifetime: Duration,
        identity: InitiatorTransitionIdentity,
    ) -> Result<(), anyhow::Error> {
        if lifetime.is_zero() || lifetime > INITIATOR_RECOVERY_LIFETIME {
            return Err(anyhow!("invalid initiator recovery lifetime"));
        }
        if !self.matches_transition_identity_fields(&identity) {
            return Err(anyhow!(
                "initiator recovery identity does not match reservation"
            ));
        }
        if identity.transition_id == [0; 16] {
            return Err(anyhow!(
                "initiator recovery requires a responder transition id"
            ));
        }
        if self
            .state
            .compare_exchange(
                RESERVATION_PENDING,
                RESERVATION_SUSPENDED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(anyhow!("session transition is no longer pending"));
        }
        let store = self.store.clone();
        store.expire_in_doubt_sessions();
        // Detach the store before retention. This prevents a store-to-map-to-
        // reservation ownership cycle while the reservation is suspended.
        self.store = PeerSessionStore::default();
        let recovery_quota = match self.recovery_quota.lock().unwrap().take() {
            Some(quota) => quota,
            None => {
                self.store = store;
                self.state.store(RESERVATION_PENDING, Ordering::Release);
                self.cancel();
                return Err(anyhow!("initiator recovery permit is missing"));
            }
        };
        match store.retain_in_doubt_reservation(self, identity, lifetime, recovery_quota) {
            Ok(()) => Ok(()),
            Err((error, mut reservation, recovery_quota)) => {
                reservation.store = store;
                *reservation.recovery_quota.lock().unwrap() = Some(recovery_quota);
                reservation
                    .state
                    .store(RESERVATION_PENDING, Ordering::Release);
                drop(reservation);
                Err(error)
            }
        }
    }

    /// Retain this reservation after an ambiguous confirmation result.
    pub fn suspend(self, lifetime: Duration) -> Result<(), anyhow::Error> {
        let identity = self.transition_identity();
        self.suspend_with_identity(lifetime, identity)
    }

    /// Retain this reservation with the authenticated peer session metadata.
    ///
    /// The peer metadata differs from a local newly created session metadata.
    /// The remaining identity fields still come from this reservation.
    pub fn suspend_with_session_metadata(
        self,
        session_metadata_id: uuid::Uuid,
        lifetime: Duration,
    ) -> Result<(), anyhow::Error> {
        let identity = self.transition_identity_with_session_metadata(session_metadata_id);
        self.suspend_with_identity(lifetime, identity)
    }

    pub fn cancel(&self) {
        if self
            .state
            .compare_exchange(
                RESERVATION_PENDING,
                RESERVATION_CANCELED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        self.store.cancel_initiator_reservation(self);
        self.release_recovery_quota();
    }

    pub fn commit(&self) -> Result<Arc<PeerSession>, anyhow::Error> {
        if self
            .state
            .compare_exchange(
                RESERVATION_PENDING,
                RESERVATION_COMMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(anyhow!("session transition is no longer pending"));
        }

        if let Err(error) = self.store.commit_initiator_reservation(self) {
            self.store.cancel_initiator_reservation(self);
            self.state.store(RESERVATION_CANCELED, Ordering::Release);
            self.release_recovery_quota();
            return Err(error);
        }
        self.release_recovery_quota();
        Ok(self.session.clone())
    }

    /// Commit and retain the exact responder receipt as one store operation.
    pub fn commit_with_receipt(
        &self,
        receipt_identity: InitiatorTransitionIdentity,
    ) -> Result<Arc<PeerSession>, anyhow::Error> {
        self.commit_with_receipt_replacing(receipt_identity, None)
    }

    /// Commit and replace one exact earlier receipt in one store operation.
    ///
    /// The earlier receipt remains retained if this commit fails. The new
    /// receipt reuses its quota permit after a successful commit.
    pub fn commit_with_receipt_replacing(
        &self,
        receipt_identity: InitiatorTransitionIdentity,
        previous_receipt_identity: Option<InitiatorTransitionIdentity>,
    ) -> Result<Arc<PeerSession>, anyhow::Error> {
        if self
            .state
            .compare_exchange(
                RESERVATION_PENDING,
                RESERVATION_COMMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(anyhow!("session transition is no longer pending"));
        }
        if let Err(error) = self.store.commit_initiator_reservation_with_receipt(
            self,
            receipt_identity,
            previous_receipt_identity,
        ) {
            self.store.cancel_initiator_reservation(self);
            self.state.store(RESERVATION_CANCELED, Ordering::Release);
            self.release_recovery_quota();
            return Err(error);
        }
        self.release_recovery_quota();
        Ok(self.session.clone())
    }
}

impl Drop for InitiatorSessionReservation {
    fn drop(&mut self) {
        if self.state.load(Ordering::Acquire) != RESERVATION_SUSPENDED {
            self.cancel();
        }
    }
}

struct SuspendedInitiatorReservation {
    identity: InitiatorTransitionIdentity,
    reservation: InitiatorSessionReservation,
    _quota: QuotaPermit,
}

struct ResponderRecoveryRecord {
    identity: InitiatorTransitionIdentity,
    recovery: ResponderTransitionRecovery,
    created_at: Instant,
    _quota: QuotaPermit,
}

struct ResponderRecoveryBackup {
    identity: InitiatorTransitionIdentity,
    recovery: ResponderTransitionRecovery,
    created_at: Instant,
    _quota: QuotaPermit,
}

struct InitiatorReceiptRecord {
    identity: InitiatorTransitionIdentity,
    session: Arc<PeerSession>,
    _quota: QuotaPermit,
}

#[derive(PartialEq, Clone, Eq, Hash, Debug)]
pub struct SessionKey {
    network_name: String,
    peer_id: PeerId,
}

impl SessionKey {
    pub fn new(network_name: String, peer_id: PeerId) -> Self {
        Self {
            network_name,
            peer_id,
        }
    }
}

#[derive(Clone)]
pub struct PeerSessionStore {
    sessions: Arc<DashMap<SessionKey, PeerSessionEntry>>,
    pending_creates: Arc<DashMap<SessionKey, Arc<PeerSession>>>,
    in_doubt_initiators: Arc<DashMap<SessionKey, SuspendedInitiatorReservation>>,
    responder_recoveries: Arc<DashMap<SessionKey, ResponderRecoveryRecord>>,
    initiator_receipts: Arc<DashMap<SessionKey, InitiatorReceiptRecord>>,
    creation_lock: Arc<Mutex<()>>,
}

struct PeerSessionEntry {
    session: Arc<PeerSession>,
    last_used_at: AtomicCell<Instant>,
}

impl PeerSessionEntry {
    fn new(session: Arc<PeerSession>) -> Self {
        Self {
            session,
            last_used_at: AtomicCell::new(Instant::now()),
        }
    }

    fn touch(&self) {
        self.last_used_at.store(Instant::now());
    }
}

impl Default for PeerSessionStore {
    fn default() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            pending_creates: Arc::new(DashMap::new()),
            in_doubt_initiators: Arc::new(DashMap::new()),
            responder_recoveries: Arc::new(DashMap::new()),
            initiator_receipts: Arc::new(DashMap::new()),
            creation_lock: Arc::new(Mutex::new(())),
        }
    }
}

impl PeerSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store one reservation without a timer-based rollback.
    fn retain_in_doubt_reservation(
        &self,
        reservation: InitiatorSessionReservation,
        identity: InitiatorTransitionIdentity,
        _lifetime: Duration,
        recovery_quota: QuotaPermit,
    ) -> Result<(), (anyhow::Error, InitiatorSessionReservation, QuotaPermit)> {
        let _guard = self.creation_lock.lock().unwrap();
        if self.in_doubt_initiators.contains_key(&identity.session_key) {
            return Err((
                anyhow!("an initiator transition is already in doubt"),
                reservation,
                recovery_quota,
            ));
        }
        self.in_doubt_initiators.insert(
            identity.session_key.clone(),
            SuspendedInitiatorReservation {
                identity,
                reservation,
                _quota: recovery_quota,
            },
        );
        Ok(())
    }

    fn reserve_responder_recovery_quota_locked(
        &self,
        key: &SessionKey,
        prepared: &UpsertResponderSessionReturn,
    ) -> Result<QuotaPermit, anyhow::Error> {
        if self.responder_recoveries.contains_key(key) {
            return Err(anyhow!("responder recovery proof is already pending"));
        }
        let principal = prepared
            .session
            .peer_static_pubkey_with_pending()
            .ok_or_else(|| anyhow!("responder recovery requires an authenticated principal"))?;
        let principal_records = self
            .responder_recoveries
            .iter()
            .filter(|entry| {
                entry.recovery.session.peer_static_pubkey_with_pending() == Some(principal)
            })
            .count();
        if principal_records >= MAX_RESPONDER_RECOVERIES_PER_PRINCIPAL {
            return Err(anyhow!("responder recovery principal capacity is full"));
        }
        if !try_reserve_global(
            &RESPONDER_RECOVERY_RECORD_COUNT,
            MAX_RESPONDER_RECOVERY_RECORDS,
        ) {
            return Err(anyhow!("responder recovery capacity is full"));
        }
        Ok(QuotaPermit {
            counter: &RESPONDER_RECOVERY_RECORD_COUNT,
        })
    }

    fn record_responder_recovery_locked(
        &self,
        key: &SessionKey,
        prepared: &UpsertResponderSessionReturn,
        quota: QuotaPermit,
    ) {
        let mut identity = InitiatorTransitionIdentity::new(
            key.clone(),
            prepared.session.metadata_session_id(),
            prepared.action,
            prepared.session_generation,
            prepared.initial_epoch,
            prepared.transition_id,
            InitiatorTransitionIdentity::digest_root_key(
                &prepared
                    .root_key
                    .unwrap_or_else(|| prepared.session.root_key()),
            ),
        );
        identity.transition_revision = prepared.transition_token();
        self.responder_recoveries.insert(
            key.clone(),
            ResponderRecoveryRecord {
                identity,
                recovery: ResponderTransitionRecovery {
                    session: prepared.session.clone(),
                    action: prepared.action,
                    session_generation: prepared.session_generation,
                    root_key: prepared
                        .root_key
                        .unwrap_or_else(|| prepared.session.root_key()),
                    initial_epoch: prepared.initial_epoch,
                    transition_id: prepared.transition_id,
                    transition_revision: prepared.transition_token(),
                },
                created_at: Instant::now(),
                _quota: quota,
            },
        );
    }

    fn expire_responder_recoveries_locked(&self, lifetime: Duration) -> usize {
        let now = Instant::now();
        let expired = self
            .responder_recoveries
            .iter()
            .filter_map(|entry| {
                (now.saturating_duration_since(entry.created_at) >= lifetime)
                    .then(|| entry.key().clone())
            })
            .collect::<Vec<_>>();
        let mut removed = 0;
        for key in expired {
            if let Some((_, record)) = self.responder_recoveries.remove(&key) {
                record.recovery.session.invalidate();
                removed += 1;
            }
        }
        removed
    }

    fn expire_responder_recoveries(&self) -> usize {
        let _guard = self.creation_lock.lock().unwrap();
        self.expire_responder_recoveries_locked(INITIATOR_RECOVERY_LIFETIME)
    }

    pub fn consume_responder_recovery(&self, identity: &InitiatorTransitionIdentity) -> bool {
        self.expire_responder_recoveries();
        let _guard = self.creation_lock.lock().unwrap();
        let Some(entry) = self.responder_recoveries.get(&identity.session_key) else {
            return false;
        };
        if !entry.identity.matches_authenticated_fields(identity) {
            return false;
        }
        drop(entry);
        self.responder_recoveries
            .remove_if(&identity.session_key, |_, proof| {
                proof.identity.matches_authenticated_fields(identity)
            })
            .is_some()
    }

    /// Remove one committed responder proof after the authenticated retry.
    pub fn acknowledge_responder_recovery(
        &self,
        key: &SessionKey,
        transition_id: [u8; 16],
    ) -> bool {
        self.expire_responder_recoveries();
        let _guard = self.creation_lock.lock().unwrap();
        let Some(entry) = self.responder_recoveries.get(key) else {
            return false;
        };
        if entry.identity.transition_id != transition_id {
            return false;
        }
        drop(entry);
        self.responder_recoveries
            .remove_if(key, |_, proof| {
                proof.identity.transition_id == transition_id
            })
            .is_some()
    }

    pub fn has_responder_recovery(&self, key: &SessionKey) -> bool {
        self.expire_responder_recoveries();
        self.responder_recoveries.contains_key(key)
    }

    pub fn has_pending_create(&self, key: &SessionKey) -> bool {
        self.pending_creates.contains_key(key)
    }

    pub fn responder_recovery_id(&self, key: &SessionKey) -> Option<[u8; 16]> {
        self.expire_responder_recoveries();
        self.responder_recoveries
            .get(key)
            .map(|entry| entry.identity.transition_id)
    }

    /// Retain an initiator session until the responder acknowledges the commit.
    pub fn record_initiator_receipt(
        &self,
        identity: InitiatorTransitionIdentity,
        session: Arc<PeerSession>,
    ) -> Result<(), anyhow::Error> {
        if identity.transition_id == [0; 16] {
            return Err(anyhow!("initiator receipt requires a transition id"));
        }
        let _guard = self.creation_lock.lock().unwrap();
        if let Some(existing) = self.initiator_receipts.get(&identity.session_key) {
            if existing.identity.matches_authenticated_fields(&identity)
                && Arc::ptr_eq(&existing.session, &session)
            {
                return Ok(());
            }
            return Err(anyhow!("initiator receipt is awaiting acknowledgement"));
        }
        if !try_reserve_global(
            &INITIATOR_RECEIPT_RECORD_COUNT,
            MAX_INITIATOR_RECEIPT_RECORDS,
        ) {
            return Err(anyhow!("initiator receipt capacity is full"));
        }
        self.initiator_receipts.insert(
            identity.session_key.clone(),
            InitiatorReceiptRecord {
                identity,
                session,
                _quota: QuotaPermit {
                    counter: &INITIATOR_RECEIPT_RECORD_COUNT,
                },
            },
        );
        Ok(())
    }

    pub fn initiator_receipt_id(&self, key: &SessionKey) -> Option<[u8; 16]> {
        self.initiator_receipts
            .get(key)
            .map(|entry| entry.identity.transition_id)
    }

    /// Return the exact identity that pins an initiator session.
    ///
    /// Callers use this identity when a receipt acknowledgement must match
    /// the authenticated transition fields, not only the transition token.
    pub fn initiator_receipt_identity(
        &self,
        key: &SessionKey,
    ) -> Option<InitiatorTransitionIdentity> {
        self.initiator_receipts
            .get(key)
            .map(|entry| entry.identity.clone())
    }

    pub fn acknowledge_initiator_receipt(&self, key: &SessionKey, transition_id: [u8; 16]) -> bool {
        let _guard = self.creation_lock.lock().unwrap();
        let Some(entry) = self.initiator_receipts.get(key) else {
            return false;
        };
        if entry.identity.transition_id != transition_id {
            return false;
        }
        drop(entry);
        self.initiator_receipts
            .remove_if(key, |_, receipt| {
                receipt.identity.transition_id == transition_id
            })
            .is_some()
    }

    pub fn acknowledge_initiator_receipt_exact(
        &self,
        identity: &InitiatorTransitionIdentity,
    ) -> bool {
        let _guard = self.creation_lock.lock().unwrap();
        let Some(entry) = self.initiator_receipts.get(&identity.session_key) else {
            return false;
        };
        if !entry.identity.matches_authenticated_fields(identity) {
            return false;
        }
        drop(entry);
        self.initiator_receipts
            .remove_if(&identity.session_key, |_, receipt| {
                receipt.identity.matches_authenticated_fields(identity)
            })
            .is_some()
    }

    pub fn active_transition_id(&self, key: &SessionKey) -> Option<[u8; 16]> {
        self.sessions
            .get(key)
            .and_then(|entry| entry.session.last_committed_transition())
            .map(|transition| transition.transition_id)
    }

    pub fn active_transition_matches(&self, identity: &InitiatorTransitionIdentity) -> bool {
        self.sessions
            .get(&identity.session_key)
            .is_some_and(|entry| entry.session.committed_transition(identity).is_some())
    }

    /// Resume one hidden initiator transition only after an exact identity match.
    pub fn resume_initiator_reservation(
        &self,
        identity: &InitiatorTransitionIdentity,
    ) -> Result<InitiatorSessionReservation, anyhow::Error> {
        let _guard = self.creation_lock.lock().unwrap();
        let entry = self
            .in_doubt_initiators
            .get(&identity.session_key)
            .ok_or_else(|| anyhow!("no matching in-doubt initiator transition"))?;
        if !entry.identity.matches_authenticated_fields(identity) {
            return Err(anyhow!("in-doubt initiator transition identity mismatch"));
        }
        drop(entry);
        let (_, suspended) = self
            .in_doubt_initiators
            .remove(&identity.session_key)
            .ok_or_else(|| anyhow!("in-doubt initiator transition disappeared"))?;
        let SuspendedInitiatorReservation {
            identity: stored_identity,
            mut reservation,
            _quota: recovery_quota,
        } = suspended;
        if !reservation.matches_transition_identity_fields(&stored_identity) {
            reservation.store = self.clone();
            reservation
                .state
                .store(RESERVATION_PENDING, Ordering::Release);
            drop(_guard);
            reservation.cancel();
            return Err(anyhow!("in-doubt initiator reservation changed"));
        }
        *reservation.recovery_quota.lock().unwrap() = Some(recovery_quota);
        reservation.store = self.clone();
        reservation
            .state
            .store(RESERVATION_PENDING, Ordering::Release);
        Ok(reservation)
    }

    /// Cancel one hidden initiator transition only after an exact identity match.
    pub fn cancel_initiator_reservation_exact(
        &self,
        identity: &InitiatorTransitionIdentity,
    ) -> bool {
        let _guard = self.creation_lock.lock().unwrap();
        let Some(entry) = self.in_doubt_initiators.get(&identity.session_key) else {
            return false;
        };
        if !entry.identity.matches_authenticated_fields(identity) {
            return false;
        }
        drop(entry);
        let Some((_, suspended)) = self.in_doubt_initiators.remove(&identity.session_key) else {
            return false;
        };
        let mut reservation = suspended.reservation;
        reservation.store = self.clone();
        reservation
            .state
            .store(RESERVATION_PENDING, Ordering::Release);
        drop(_guard);
        reservation.cancel();
        true
    }

    /// Clear durable peer records after local authenticated peer removal.
    ///
    /// The retained Noise static key is required. A mismatched key leaves every
    /// record unchanged, so a peer cannot clear another peer's recovery state.
    pub fn clear_peer_records_if_static_key_matches(
        &self,
        key: &SessionKey,
        peer_static_pubkey: [u8; 32],
    ) -> bool {
        let _guard = self.creation_lock.lock().unwrap();
        let has_records = self.sessions.contains_key(key)
            || self.pending_creates.contains_key(key)
            || self.in_doubt_initiators.contains_key(key)
            || self.responder_recoveries.contains_key(key)
            || self.initiator_receipts.contains_key(key);
        if !has_records {
            return false;
        }

        let key_matches = self.sessions.get(key).is_none_or(|entry| {
            entry.session.peer_static_pubkey_with_pending() == Some(peer_static_pubkey)
        }) && self.pending_creates.get(key).is_none_or(|session| {
            session.peer_static_pubkey_with_pending() == Some(peer_static_pubkey)
        }) && self.in_doubt_initiators.get(key).is_none_or(|entry| {
            entry
                .reservation
                .peer_static_pubkey
                .or_else(|| entry.reservation.session.peer_static_pubkey_with_pending())
                == Some(peer_static_pubkey)
        }) && self.responder_recoveries.get(key).is_none_or(|entry| {
            entry.recovery.session.peer_static_pubkey_with_pending() == Some(peer_static_pubkey)
        }) && self.initiator_receipts.get(key).is_none_or(|entry| {
            entry.session.peer_static_pubkey_with_pending() == Some(peer_static_pubkey)
        });
        if !key_matches {
            return false;
        }

        // Remove every durable record while holding the ownership lock. Drop
        // and invalidate the owned sessions after the lock is released.
        let pending_create = self.pending_creates.remove(key).map(|(_, session)| session);
        let suspended = self
            .in_doubt_initiators
            .remove(key)
            .map(|(_, suspended)| suspended);
        self.responder_recoveries.remove(key);
        self.initiator_receipts.remove(key);
        let active_session = self.sessions.remove(key).map(|(_, entry)| entry.session);
        drop(_guard);

        if let Some(session) = pending_create {
            session.invalidate();
        }
        if let Some(suspended) = suspended {
            let mut reservation = suspended.reservation;
            reservation.store = self.clone();
            reservation
                .state
                .store(RESERVATION_PENDING, Ordering::Release);
            reservation.cancel();
        }
        if let Some(session) = active_session {
            session.invalidate();
        }
        true
    }

    /// No timer may cancel an ambiguous hidden initiator transition.
    pub fn expire_in_doubt_sessions(&self) -> usize {
        // An ambiguous transition is never rolled back by a timer. The
        // authenticated retry or an explicit authenticated reset owns cleanup.
        0
    }

    pub fn in_doubt_reservation_count(&self) -> usize {
        self.in_doubt_initiators.len()
    }

    pub fn in_doubt_identity(&self, key: &SessionKey) -> Option<InitiatorTransitionIdentity> {
        self.expire_in_doubt_sessions();
        self.in_doubt_initiators
            .get(key)
            .map(|entry| entry.identity.clone())
    }

    /// Return the retained peer static key for one hidden transition.
    pub fn in_doubt_peer_static_pubkey(&self, key: &SessionKey) -> Option<[u8; 32]> {
        self.expire_in_doubt_sessions();
        self.in_doubt_initiators.get(key).and_then(|entry| {
            entry
                .reservation
                .peer_static_pubkey
                .or_else(|| entry.reservation.session.peer_static_pubkey_with_pending())
        })
    }

    /// Check one exact in-doubt transition against a Noise static key.
    ///
    /// The check reads the reservation and its pending session key only.
    /// It does not consume or mutate recovery state.
    pub fn check_in_doubt_recovery_peer_static_pubkey(
        &self,
        identity: &InitiatorTransitionIdentity,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<bool, anyhow::Error> {
        self.expire_in_doubt_sessions();
        let entry = self
            .in_doubt_initiators
            .get(&identity.session_key)
            .ok_or_else(|| anyhow!("no matching in-doubt initiator transition"))?;
        if !entry.identity.matches_authenticated_fields(identity) {
            return Err(anyhow!("in-doubt initiator transition identity mismatch"));
        }
        let reservation_key = entry.reservation.peer_static_pubkey;
        let session_key = entry.reservation.session.peer_static_pubkey_with_pending();
        if reservation_key.is_some() && session_key.is_some() && reservation_key != session_key {
            return Err(anyhow!("in-doubt peer static key state is inconsistent"));
        }
        let expected = reservation_key.or(session_key);
        Ok(expected.is_some() && expected == peer_static_pubkey)
    }

    pub fn get(&self, key: &SessionKey) -> Option<Arc<PeerSession>> {
        if let Some(entry) = self.sessions.get(key) {
            if entry.session.is_valid() {
                entry.touch();
                return Some(entry.session.clone());
            }
            let invalid = entry.session.clone();
            drop(entry);
            self.sessions
                .remove_if(key, |_, current| Arc::ptr_eq(&current.session, &invalid));
        }
        None
    }

    pub fn peek(&self, key: &SessionKey) -> Option<Arc<PeerSession>> {
        self.sessions
            .get(key)
            .filter(|entry| entry.session.is_valid())
            .map(|entry| entry.session.clone())
    }

    pub fn touch_if_same(&self, key: &SessionKey, session: &Arc<PeerSession>) {
        if let Some(entry) = self.sessions.get(key)
            && Arc::ptr_eq(&entry.session, session)
        {
            entry.touch();
        }
    }

    pub fn remove(&self, key: &SessionKey) {
        let _guard = self.creation_lock.lock().unwrap();
        self.sessions.remove(key);
    }

    pub fn remove_if_same(&self, key: &SessionKey, session: &Arc<PeerSession>) {
        let _guard = self.creation_lock.lock().unwrap();
        self.sessions
            .remove_if(key, |_, entry| Arc::ptr_eq(&entry.session, session));
    }

    pub fn insert_session(&self, key: SessionKey, session: Arc<PeerSession>) {
        let _guard = self.creation_lock.lock().unwrap();
        self.pending_creates.remove(&key);
        self.sessions.insert(key, PeerSessionEntry::new(session));
    }

    /// Prepare an initiator transition without publishing or changing traffic
    /// keys in the active session.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_initiator_action(
        &self,
        key: &SessionKey,
        action: PeerSessionAction,
        b_session_generation: u32,
        root_key_32: Option<[u8; 32]>,
        initial_epoch: u32,
        send_algorithm: String,
        recv_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<InitiatorSessionReservation, anyhow::Error> {
        self.prepare_initiator_action_with_transition_id(
            key,
            action,
            b_session_generation,
            root_key_32,
            initial_epoch,
            send_algorithm,
            recv_algorithm,
            peer_static_pubkey,
            new_transition_id(),
        )
    }

    /// Prepare an initiator transition bound to the responder token.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_initiator_action_with_transition_id(
        &self,
        key: &SessionKey,
        action: PeerSessionAction,
        b_session_generation: u32,
        root_key_32: Option<[u8; 32]>,
        initial_epoch: u32,
        send_algorithm: String,
        recv_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
        transition_id: [u8; 16],
    ) -> Result<InitiatorSessionReservation, anyhow::Error> {
        self.expire_in_doubt_sessions();
        let _creation_guard = self.creation_lock.lock().unwrap();
        if self.in_doubt_initiators.contains_key(key) {
            return Err(anyhow!("session transition is awaiting exact recovery"));
        }
        if self.responder_recoveries.contains_key(key) {
            return Err(anyhow!(
                "responder recovery proof is awaiting exact recovery"
            ));
        }
        // Reserve the recovery slot before any handshake message can make
        // the responder commit this transition. The permit moves into an
        // in-doubt record if the confirmation result is ambiguous.
        if !try_reserve_global(&IN_DOUBT_RESERVATION_COUNT, MAX_IN_DOUBT_RESERVATIONS) {
            return Err(anyhow!("initiator recovery capacity is full"));
        }
        let recovery_quota = QuotaPermit {
            counter: &IN_DOUBT_RESERVATION_COUNT,
        };
        let result = match action {
            PeerSessionAction::Join => {
                let session = self
                    .peek(key)
                    .ok_or_else(|| anyhow!("no local session for JOIN"))?;
                session.check_encrypt_algo_same(&send_algorithm, &recv_algorithm)?;
                session.check_peer_static_pubkey(peer_static_pubkey)?;
                if session.session_generation() != b_session_generation {
                    return Err(anyhow!("JOIN generation mismatch"));
                }
                Ok(InitiatorSessionReservation {
                    transition_revision: session.transition_revision(),
                    root_key: session.root_key(),
                    initial_epoch,
                    transition_id,
                    session_generation: b_session_generation,
                    store: self.clone(),
                    key: key.clone(),
                    session,
                    action,
                    send_algorithm,
                    recv_algorithm,
                    peer_static_pubkey,
                    recovery_quota: Mutex::new(None),
                    state: AtomicU8::new(RESERVATION_PENDING),
                })
            }
            PeerSessionAction::Sync => {
                if self.pending_creates.contains_key(key) {
                    return Err(anyhow!("session creation is pending"));
                }
                let session = self
                    .peek(key)
                    .ok_or_else(|| anyhow!("no local session for SYNC"))?;
                session.check_encrypt_algo_same(&send_algorithm, &recv_algorithm)?;
                session.check_peer_static_pubkey(peer_static_pubkey)?;
                let root_key = root_key_32.ok_or_else(|| anyhow!("missing root_key"))?;
                let (active_generation, _current_root_key, reserved_epoch, transition_revision) =
                    session.prepare_sync_transition_at(initial_epoch)?;
                if let Err(error) = session.reserve_peer_static_pubkey(peer_static_pubkey) {
                    session.cancel_reserved_sync(transition_revision, reserved_epoch);
                    return Err(error);
                }
                if active_generation != b_session_generation {
                    session.cancel_reserved_sync(transition_revision, reserved_epoch);
                    session.cancel_reserved_peer_static_pubkey();
                    return Err(anyhow!("SYNC generation mismatch"));
                }
                Ok(InitiatorSessionReservation {
                    store: self.clone(),
                    key: key.clone(),
                    session,
                    action,
                    session_generation: b_session_generation,
                    root_key,
                    initial_epoch,
                    transition_id,
                    transition_revision,
                    send_algorithm,
                    recv_algorithm,
                    peer_static_pubkey,
                    recovery_quota: Mutex::new(None),
                    state: AtomicU8::new(RESERVATION_PENDING),
                })
            }
            PeerSessionAction::Create => {
                if self.pending_creates.contains_key(key) {
                    return Err(anyhow!("session creation is pending"));
                }
                if self.peek(key).is_some() {
                    return Err(anyhow!("session already exists; use SYNC"));
                }
                let root_key = root_key_32.ok_or_else(|| anyhow!("missing root_key"))?;
                let session = Arc::new(PeerSession::new(
                    key.peer_id,
                    root_key,
                    b_session_generation,
                    initial_epoch,
                    send_algorithm.clone(),
                    recv_algorithm.clone(),
                    peer_static_pubkey,
                ));
                session.initialize_transition_revision(1);
                match self.pending_creates.entry(key.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(session.clone());
                    }
                    Entry::Occupied(_) => {
                        return Err(anyhow!("session creation is pending"));
                    }
                }
                Ok(InitiatorSessionReservation {
                    store: self.clone(),
                    key: key.clone(),
                    session,
                    action,
                    session_generation: b_session_generation,
                    root_key,
                    initial_epoch,
                    // A new session starts at revision zero. The first
                    // transition uses revision one on both peers.
                    transition_revision: 1,
                    transition_id,
                    send_algorithm,
                    recv_algorithm,
                    peer_static_pubkey,
                    recovery_quota: Mutex::new(None),
                    state: AtomicU8::new(RESERVATION_PENDING),
                })
            }
        };
        match result {
            Ok(reservation) => {
                *reservation.recovery_quota.lock().unwrap() = Some(recovery_quota);
                Ok(reservation)
            }
            Err(error) => {
                drop(recovery_quota);
                Err(error)
            }
        }
    }

    fn cancel_initiator_reservation(&self, reservation: &InitiatorSessionReservation) {
        let _guard = self.creation_lock.lock().unwrap();
        match reservation.action {
            PeerSessionAction::Create => {
                self.pending_creates
                    .remove_if(&reservation.key, |_, current| {
                        Arc::ptr_eq(current, &reservation.session)
                    });
            }
            PeerSessionAction::Sync => {
                reservation.session.cancel_reserved_sync(
                    reservation.transition_revision,
                    reservation.initial_epoch,
                );
            }
            PeerSessionAction::Join => {}
        }
    }

    fn commit_initiator_reservation(
        &self,
        reservation: &InitiatorSessionReservation,
    ) -> Result<(), anyhow::Error> {
        let _guard = self.creation_lock.lock().unwrap();
        self.commit_initiator_reservation_locked(reservation)
    }

    /// Commit one initiator reservation and install its receipt atomically.
    ///
    /// The receipt quota and conflict checks run before the reservation can
    /// publish keys. The receipt becomes visible only after the commit works.
    fn commit_initiator_reservation_with_receipt(
        &self,
        reservation: &InitiatorSessionReservation,
        receipt_identity: InitiatorTransitionIdentity,
        previous_receipt_identity: Option<InitiatorTransitionIdentity>,
    ) -> Result<(), anyhow::Error> {
        if receipt_identity.transition_id == [0; 16] {
            return Err(anyhow!("initiator receipt requires a transition id"));
        }
        if !reservation.matches_transition_identity_fields(&receipt_identity) {
            return Err(anyhow!(
                "initiator receipt identity does not match reservation"
            ));
        }

        let _guard = self.creation_lock.lock().unwrap();
        let existing_identity = self
            .initiator_receipts
            .get(&receipt_identity.session_key)
            .map(|entry| entry.identity.clone());

        let Some(previous_receipt_identity) = previous_receipt_identity else {
            if existing_identity.is_some() {
                return Err(anyhow!("initiator receipt is awaiting acknowledgement"));
            }

            // Reserve the permit before session mutation. If commit fails,
            // the permit drops here and no receipt record is published.
            let receipt_quota = if !try_reserve_global(
                &INITIATOR_RECEIPT_RECORD_COUNT,
                MAX_INITIATOR_RECEIPT_RECORDS,
            ) {
                return Err(anyhow!("initiator receipt capacity is full"));
            } else {
                QuotaPermit {
                    counter: &INITIATOR_RECEIPT_RECORD_COUNT,
                }
            };

            if let Err(error) = self.commit_initiator_reservation_locked(reservation) {
                drop(receipt_quota);
                return Err(error);
            }

            self.initiator_receipts.insert(
                receipt_identity.session_key.clone(),
                InitiatorReceiptRecord {
                    identity: receipt_identity,
                    session: reservation.session.clone(),
                    _quota: receipt_quota,
                },
            );
            return Ok(());
        };

        match existing_identity {
            Some(existing_identity) if existing_identity == previous_receipt_identity => {
                // Hold the previous record and its permit while commit runs. This
                // keeps the global count bounded and restores the exact record on any
                // commit error.
                let (_, previous_receipt) = self
                    .initiator_receipts
                    .remove(&receipt_identity.session_key)
                    .ok_or_else(|| anyhow!("initiator receipt disappeared before replacement"))?;
                let receipt_quota = previous_receipt._quota;
                if let Err(error) = self.commit_initiator_reservation_locked(reservation) {
                    self.initiator_receipts.insert(
                        previous_receipt.identity.session_key.clone(),
                        InitiatorReceiptRecord {
                            identity: previous_receipt.identity,
                            session: previous_receipt.session,
                            _quota: receipt_quota,
                        },
                    );
                    return Err(error);
                }

                self.initiator_receipts.insert(
                    receipt_identity.session_key.clone(),
                    InitiatorReceiptRecord {
                        identity: receipt_identity,
                        session: reservation.session.clone(),
                        _quota: receipt_quota,
                    },
                );
                Ok(())
            }
            None => {
                // The exact prior receipt may be acknowledged by its original
                // in-flight ReadyReceiptAck after this handshake snapshots it.
                // Absence is unambiguous under creation_lock, so reserve a fresh
                // permit and publish the new receipt atomically with the commit.
                let receipt_quota = if !try_reserve_global(
                    &INITIATOR_RECEIPT_RECORD_COUNT,
                    MAX_INITIATOR_RECEIPT_RECORDS,
                ) {
                    return Err(anyhow!("initiator receipt capacity is full"));
                } else {
                    QuotaPermit {
                        counter: &INITIATOR_RECEIPT_RECORD_COUNT,
                    }
                };
                if let Err(error) = self.commit_initiator_reservation_locked(reservation) {
                    drop(receipt_quota);
                    return Err(error);
                }
                self.initiator_receipts.insert(
                    receipt_identity.session_key.clone(),
                    InitiatorReceiptRecord {
                        identity: receipt_identity,
                        session: reservation.session.clone(),
                        _quota: receipt_quota,
                    },
                );
                Ok(())
            }
            Some(_) => Err(anyhow!("the expected initiator receipt changed")),
        }
    }

    fn commit_initiator_reservation_locked(
        &self,
        reservation: &InitiatorSessionReservation,
    ) -> Result<(), anyhow::Error> {
        match reservation.action {
            PeerSessionAction::Create => {
                if !self
                    .pending_creates
                    .get(&reservation.key)
                    .is_some_and(|current| Arc::ptr_eq(&current, &reservation.session))
                {
                    return Err(anyhow!("initiator session creation claim changed"));
                }
                if !reservation.session.is_valid()
                    || reservation.session.transition_revision() != reservation.transition_revision
                {
                    return Err(anyhow!("initiator session changed before confirmation"));
                }
                let can_publish = match self.sessions.get(&reservation.key) {
                    None => true,
                    Some(entry) if !entry.session.is_valid() => true,
                    Some(_) => false,
                };
                if !can_publish {
                    return Err(anyhow!("session changed before initiator confirmation"));
                }
                reservation.session.record_committed_transition(
                    PeerSessionAction::Create,
                    reservation.session_generation,
                    reservation.root_key,
                    reservation.initial_epoch,
                    reservation.transition_id,
                    reservation.transition_revision,
                );
                match self.sessions.entry(reservation.key.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(PeerSessionEntry::new(reservation.session.clone()));
                    }
                    Entry::Occupied(mut entry) if !entry.get().session.is_valid() => {
                        entry.insert(PeerSessionEntry::new(reservation.session.clone()));
                    }
                    Entry::Occupied(_) => unreachable!(
                        "creation lock protects the initiator session publication check"
                    ),
                }
                self.pending_creates
                    .remove_if(&reservation.key, |_, current| {
                        Arc::ptr_eq(current, &reservation.session)
                    });
                Ok(())
            }
            PeerSessionAction::Sync => {
                let current = self
                    .sessions
                    .get(&reservation.key)
                    .ok_or_else(|| anyhow!("session disappeared before initiator confirmation"))?;
                if !Arc::ptr_eq(&current.session, &reservation.session) {
                    return Err(anyhow!("session changed before initiator confirmation"));
                }
                reservation.session.commit_reserved_sync(
                    reservation.transition_revision,
                    reservation.root_key,
                    reservation.session_generation,
                    reservation.initial_epoch,
                    reservation.transition_id,
                )
            }
            PeerSessionAction::Join => {
                let current = self
                    .sessions
                    .get(&reservation.key)
                    .ok_or_else(|| anyhow!("session disappeared before JOIN confirmation"))?;
                if !Arc::ptr_eq(&current.session, &reservation.session)
                    || reservation.session.transition_revision() != reservation.transition_revision
                {
                    return Err(anyhow!("session changed before JOIN confirmation"));
                }
                reservation.session.check_encrypt_algo_same(
                    &reservation.send_algorithm,
                    &reservation.recv_algorithm,
                )?;
                reservation
                    .session
                    .check_or_set_peer_static_pubkey(reservation.peer_static_pubkey)?;
                reservation.session.record_committed_transition(
                    PeerSessionAction::Join,
                    reservation.session_generation,
                    reservation.session.root_key(),
                    reservation.initial_epoch,
                    reservation.transition_id,
                    reservation.transition_revision,
                );
                current.touch();
                Ok(())
            }
        }
    }

    pub fn cancel_prepared_session(
        &self,
        key: &SessionKey,
        session: &Arc<PeerSession>,
        action: PeerSessionAction,
        transition_revision: Option<u64>,
        initial_epoch: u32,
    ) {
        let _guard = self.creation_lock.lock().unwrap();
        match action {
            PeerSessionAction::Create => {
                self.pending_creates
                    .remove_if(key, |_, pending| Arc::ptr_eq(pending, session));
            }
            PeerSessionAction::Sync => {
                if let Some(revision) = transition_revision {
                    session.cancel_reserved_sync(revision, initial_epoch);
                }
            }
            PeerSessionAction::Join => session.cancel_reserved_peer_static_pubkey(),
        }
    }

    /// Commit one responder transition while holding the store ownership lock.
    ///
    /// The exact session pointer and transition revision are checked before
    /// traffic keys or the store entry become active.
    pub fn commit_prepared_responder_transition(
        &self,
        key: &SessionKey,
        prepared: &UpsertResponderSessionReturn,
    ) -> Result<(), anyhow::Error> {
        let _guard = self.creation_lock.lock().unwrap();
        if prepared.proof_dependency.is_some() && !prepared.proof_cleared.load(Ordering::Acquire) {
            return Err(anyhow!(
                "responder transition requires authenticated proof confirmation"
            ));
        }
        let has_reused_proof_quota = prepared.proof_dependency.is_some();
        if has_reused_proof_quota && prepared.proof_backup.lock().unwrap().is_none() {
            return Err(anyhow!("authenticated responder proof backup is missing"));
        }
        let fresh_proof_quota = if has_reused_proof_quota {
            None
        } else {
            Some(self.reserve_responder_recovery_quota_locked(key, prepared)?)
        };
        let result = (|| -> Result<(), anyhow::Error> {
            match prepared.action {
                PeerSessionAction::Create => {
                    if !self
                        .pending_creates
                        .get(key)
                        .is_some_and(|pending| Arc::ptr_eq(&pending, &prepared.session))
                    {
                        return Err(anyhow!("responder session creation claim changed"));
                    }
                    if !prepared.session.is_valid()
                        || prepared.session.transition_revision() != prepared.transition_token()
                    {
                        return Err(anyhow!("responder session changed before confirmation"));
                    }
                    prepared.session.commit_reserved_peer_static_pubkey()?;
                    prepared.session.record_committed_transition(
                        PeerSessionAction::Create,
                        prepared.session_generation,
                        prepared
                            .root_key
                            .ok_or_else(|| anyhow!("responder CREATE has no root key"))?,
                        prepared.initial_epoch,
                        prepared.transition_id,
                        prepared.transition_token(),
                    );
                    match self.sessions.entry(key.clone()) {
                        Entry::Vacant(entry) => {
                            entry.insert(PeerSessionEntry::new(prepared.session.clone()));
                        }
                        Entry::Occupied(mut entry) if !entry.get().session.is_valid() => {
                            entry.insert(PeerSessionEntry::new(prepared.session.clone()));
                        }
                        Entry::Occupied(_) => {
                            return Err(anyhow!("session changed before responder confirmation"));
                        }
                    }
                    self.pending_creates
                        .remove_if(key, |_, pending| Arc::ptr_eq(pending, &prepared.session));
                    Ok(())
                }
                PeerSessionAction::Sync => {
                    let current = self.sessions.get(key).ok_or_else(|| {
                        anyhow!("responder session disappeared before confirmation")
                    })?;
                    if !Arc::ptr_eq(&current.session, &prepared.session) {
                        return Err(anyhow!("session changed before responder confirmation"));
                    }
                    let root_key = prepared
                        .root_key
                        .ok_or_else(|| anyhow!("responder SYNC has no root key"))?;
                    prepared.session.commit_reserved_sync(
                        prepared
                            .transition_revision
                            .ok_or_else(|| anyhow!("responder SYNC has no transition revision"))?,
                        root_key,
                        prepared.session_generation,
                        prepared.initial_epoch,
                        prepared.transition_id,
                    )
                }
                PeerSessionAction::Join => {
                    let current = self.sessions.get(key).ok_or_else(|| {
                        anyhow!("responder session disappeared before confirmation")
                    })?;
                    if !Arc::ptr_eq(&current.session, &prepared.session) {
                        return Err(anyhow!("session changed before responder confirmation"));
                    }
                    if !prepared.session.is_valid()
                        || prepared.session.transition_revision() != prepared.transition_token()
                    {
                        return Err(anyhow!("responder session changed before confirmation"));
                    }
                    prepared.session.commit_reserved_peer_static_pubkey()?;
                    prepared.session.record_committed_transition(
                        PeerSessionAction::Join,
                        prepared.session_generation,
                        prepared.session.root_key(),
                        prepared.initial_epoch,
                        prepared.transition_id,
                        prepared.transition_token(),
                    );
                    Ok(())
                }
            }
        })();
        if result.is_ok() {
            let proof_quota = match fresh_proof_quota {
                Some(quota) => quota,
                None => {
                    prepared
                        .proof_backup
                        .lock()
                        .unwrap()
                        .take()
                        .expect("authenticated proof backup was checked before commit")
                        ._quota
                }
            };
            self.record_responder_recovery_locked(key, prepared, proof_quota);
            prepared.committed.store(true, Ordering::Release);
        }
        result
    }

    /// Return an already committed responder transition without staging keys.
    pub fn reconcile_active_responder_transition(
        &self,
        identity: &InitiatorTransitionIdentity,
    ) -> Result<Option<ResponderTransitionRecovery>, anyhow::Error> {
        self.expire_in_doubt_sessions();
        self.expire_responder_recoveries();
        let _guard = self.creation_lock.lock().unwrap();
        if let Some(entry) = self.responder_recoveries.get(&identity.session_key)
            && entry.identity.matches_authenticated_fields(identity)
        {
            return Ok(Some(entry.recovery.clone()));
        }
        let Some(entry) = self.sessions.get(&identity.session_key) else {
            return Ok(None);
        };
        let session = entry.session.clone();
        if !session.is_valid() || session.metadata_session_id() != identity.session_metadata_id {
            return Ok(None);
        }
        let Some(committed) = session.committed_transition(identity) else {
            return Ok(None);
        };
        Ok(Some(ResponderTransitionRecovery {
            session,
            action: committed.action,
            session_generation: committed.session_generation,
            root_key: committed.root_key,
            initial_epoch: committed.initial_epoch,
            transition_id: committed.transition_id,
            transition_revision: committed.transition_revision,
        }))
    }

    pub fn prepare_responder_session(
        &self,
        key: &SessionKey,
        send_algorithm: String,
        recv_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<UpsertResponderSessionReturn, anyhow::Error> {
        self.expire_in_doubt_sessions();
        let _creation_guard = self.creation_lock.lock().unwrap();
        self.prepare_responder_session_locked(
            key,
            send_algorithm,
            recv_algorithm,
            peer_static_pubkey,
            false,
        )
    }

    /// Stage one responder transition while retaining the previous proof.
    /// The proof is removed only after authenticated peer confirmation.
    #[allow(clippy::too_many_arguments)]
    pub fn acknowledge_and_prepare_responder_session(
        &self,
        key: &SessionKey,
        acknowledged_transition_id: [u8; 16],
        send_algorithm: String,
        recv_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<UpsertResponderSessionReturn, anyhow::Error> {
        self.prepare_responder_session_with_recovery_proof(
            key,
            acknowledged_transition_id,
            send_algorithm,
            recv_algorithm,
            peer_static_pubkey,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_responder_session_with_recovery_proof(
        &self,
        key: &SessionKey,
        acknowledged_transition_id: [u8; 16],
        send_algorithm: String,
        recv_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<UpsertResponderSessionReturn, anyhow::Error> {
        self.expire_responder_recoveries();
        let _guard = self.creation_lock.lock().unwrap();
        let Some(proof) = self.responder_recoveries.get(key) else {
            return Err(anyhow!("no responder recovery proof is pending"));
        };
        if proof.identity.transition_id != acknowledged_transition_id {
            return Err(anyhow!("responder recovery acknowledgement mismatch"));
        }
        drop(proof);
        let mut prepared = self.prepare_responder_session_locked(
            key,
            send_algorithm,
            recv_algorithm,
            peer_static_pubkey,
            true,
        )?;
        prepared.proof_dependency = Some(acknowledged_transition_id);
        Ok(prepared)
    }

    /// Remove the previous proof after authenticated final handshake data.
    pub fn authenticate_prepared_responder_transition(
        &self,
        key: &SessionKey,
        prepared: &UpsertResponderSessionReturn,
        acknowledged_transition_id: [u8; 16],
    ) -> Result<(), anyhow::Error> {
        let _guard = self.creation_lock.lock().unwrap();
        if prepared.prepared_key != *key
            || prepared.proof_dependency != Some(acknowledged_transition_id)
        {
            return Err(anyhow!("responder proof dependency mismatch"));
        }
        if prepared.proof_cleared.load(Ordering::Acquire) {
            return Ok(());
        }
        let live = match prepared.action {
            PeerSessionAction::Create => self
                .pending_creates
                .get(key)
                .is_some_and(|pending| Arc::ptr_eq(&pending, &prepared.session)),
            PeerSessionAction::Sync | PeerSessionAction::Join => self
                .sessions
                .get(key)
                .is_some_and(|entry| Arc::ptr_eq(&entry.session, &prepared.session)),
        };
        if !live {
            return Err(anyhow!("responder transition is no longer pending"));
        }
        let Some(proof) = self.responder_recoveries.get(key) else {
            return Err(anyhow!("responder recovery proof is missing"));
        };
        if proof.identity.transition_id != acknowledged_transition_id {
            return Err(anyhow!("responder recovery proof mismatch"));
        }
        drop(proof);
        let Some((_, proof)) = self.responder_recoveries.remove(key) else {
            return Err(anyhow!("responder recovery proof changed"));
        };
        if proof.identity.transition_id != acknowledged_transition_id {
            self.responder_recoveries.insert(key.clone(), proof);
            return Err(anyhow!("responder recovery proof changed"));
        }
        *prepared.proof_backup.lock().unwrap() = Some(ResponderRecoveryBackup {
            identity: proof.identity,
            recovery: proof.recovery,
            created_at: proof.created_at,
            _quota: proof._quota,
        });
        prepared.proof_cleared.store(true, Ordering::Release);
        Ok(())
    }

    fn restore_responder_recovery(&self, prepared: &UpsertResponderSessionReturn) {
        let Some(backup) = prepared.proof_backup.lock().unwrap().take() else {
            prepared.proof_cleared.store(false, Ordering::Release);
            return;
        };
        let _guard = self.creation_lock.lock().unwrap();
        if self
            .responder_recoveries
            .contains_key(&prepared.prepared_key)
        {
            drop(backup);
            prepared.proof_cleared.store(false, Ordering::Release);
            return;
        }
        self.responder_recoveries.insert(
            prepared.prepared_key.clone(),
            ResponderRecoveryRecord {
                identity: backup.identity,
                recovery: backup.recovery,
                created_at: backup.created_at,
                _quota: backup._quota,
            },
        );
        prepared.proof_cleared.store(false, Ordering::Release);
    }

    fn prepare_responder_session_locked(
        &self,
        key: &SessionKey,
        send_algorithm: String,
        recv_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
        allow_existing_proof: bool,
    ) -> Result<UpsertResponderSessionReturn, anyhow::Error> {
        if self.in_doubt_initiators.contains_key(key) {
            return Err(anyhow!("session transition is awaiting exact recovery"));
        }
        if !allow_existing_proof && self.responder_recoveries.contains_key(key) {
            return Err(anyhow!(
                "responder recovery proof is awaiting exact recovery"
            ));
        }
        if let Some(session) = self.get(key) {
            session.check_encrypt_algo_same(&send_algorithm, &recv_algorithm)?;
            let (session_generation, root_key, initial_epoch, transition_revision) =
                session.prepare_sync_transition()?;
            let transition_id = new_transition_id();
            if let Err(error) = session.reserve_peer_static_pubkey(peer_static_pubkey) {
                session.cancel_reserved_sync(transition_revision, initial_epoch);
                return Err(error);
            }
            return Ok(UpsertResponderSessionReturn {
                session,
                action: PeerSessionAction::Sync,
                session_generation,
                root_key: Some(root_key),
                initial_epoch,
                transition_revision: Some(transition_revision),
                transition_id,
                proof_dependency: None,
                proof_cleared: AtomicBool::new(false),
                committed: AtomicBool::new(false),
                proof_backup: Mutex::new(None),
                prepared_store: self.clone(),
                prepared_key: key.clone(),
            });
        }

        let root_key = PeerSession::new_root_key();
        let session_generation = 1;
        let initial_epoch = 0;
        let transition_id = new_transition_id();
        let session = Arc::new(PeerSession::new(
            key.peer_id,
            root_key,
            session_generation,
            initial_epoch,
            send_algorithm,
            recv_algorithm,
            peer_static_pubkey,
        ));
        session.initialize_transition_revision(1);
        match self.pending_creates.entry(key.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(session.clone());
            }
            Entry::Occupied(_) => {
                return Err(anyhow!("session creation is already pending"));
            }
        }
        Ok(UpsertResponderSessionReturn {
            session,
            action: PeerSessionAction::Create,
            session_generation,
            root_key: Some(root_key),
            initial_epoch,
            transition_revision: None,
            transition_id,
            proof_dependency: None,
            proof_cleared: AtomicBool::new(false),
            committed: AtomicBool::new(false),
            proof_backup: Mutex::new(None),
            prepared_store: self.clone(),
            prepared_key: key.clone(),
        })
    }

    pub fn evict_unused_sessions(&self) {
        self.evict_unused_sessions_idle(SESSION_IDLE_TIMEOUT);
    }

    pub fn evict_unused_sessions_idle(&self, idle: Duration) {
        self.expire_in_doubt_sessions();
        let _guard = self.creation_lock.lock().unwrap();
        self.expire_responder_recoveries_locked(INITIATOR_RECOVERY_LIFETIME);
        let now = Instant::now();
        self.sessions.retain(|_key, entry| {
            entry.session.is_valid()
                && (Arc::strong_count(&entry.session) > 1
                    || now.saturating_duration_since(entry.last_used_at.load()) < idle)
        });
        shrink_dashmap(&self.sessions, None);
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self))]
    pub fn apply_initiator_action(
        &self,
        key: &SessionKey,
        action: PeerSessionAction,
        b_session_generation: u32,
        root_key_32: Option<[u8; 32]>,
        initial_epoch: u32,
        send_algorithm: String,
        recv_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<Arc<PeerSession>, anyhow::Error> {
        tracing::event!(tracing::Level::INFO, "apply_initiator_action {:?}", key);
        let reservation = self.prepare_initiator_action(
            key,
            action,
            b_session_generation,
            root_key_32,
            initial_epoch,
            send_algorithm,
            recv_algorithm,
            peer_static_pubkey,
        )?;
        reservation.commit()
    }
}

pub struct PeerSession {
    peer_id: PeerId,
    metadata_session_id: uuid::Uuid,
    peer_static_pubkey: RwLock<Option<[u8; 32]>>,
    datagram: SecureDatagramSession,
    transition: Mutex<SessionTransition>,
    invalidated: AtomicBool,
}

struct SessionTransition {
    revision: u64,
    reserved_epoch: u32,
    pending_epoch: Option<u32>,
    pending_peer_static_pubkey: Option<[u8; 32]>,
    committed_history: VecDeque<CommittedTransition>,
}

#[derive(Clone, Copy)]
struct CommittedTransition {
    action: PeerSessionAction,
    session_generation: u32,
    root_key: [u8; 32],
    initial_epoch: u32,
    transition_id: [u8; 16],
    transition_revision: u64,
}

impl std::fmt::Debug for PeerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerSession")
            .field("peer_id", &self.peer_id)
            .field("peer_static_pubkey", &self.peer_static_pubkey)
            .field("datagram", &self.datagram)
            .finish()
    }
}

impl PeerSession {
    const SYNC_RX_GRACE_AFTER_MS: u64 = SecureDatagramSession::SYNC_RX_GRACE_AFTER_MS;

    pub fn new(
        peer_id: PeerId,
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        send_cipher_algorithm: String,
        recv_cipher_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Self {
        Self {
            peer_id,
            metadata_session_id: uuid::Uuid::new_v4(),
            peer_static_pubkey: RwLock::new(peer_static_pubkey),
            datagram: SecureDatagramSession::new(
                root_key,
                session_generation,
                initial_epoch,
                send_cipher_algorithm,
                recv_cipher_algorithm,
            ),
            transition: Mutex::new(SessionTransition {
                revision: 0,
                reserved_epoch: initial_epoch,
                pending_epoch: None,
                pending_peer_static_pubkey: None,
                committed_history: VecDeque::new(),
            }),
            invalidated: AtomicBool::new(false),
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn metadata_session_id(&self) -> uuid::Uuid {
        self.metadata_session_id
    }

    pub fn invalidate(&self) {
        self.invalidated.store(true, Ordering::Relaxed);
        self.datagram.invalidate();
    }

    pub fn is_valid(&self) -> bool {
        !self.invalidated.load(Ordering::Relaxed) && self.datagram.is_valid()
    }

    pub fn session_generation(&self) -> u32 {
        self.datagram.session_generation()
    }

    pub fn root_key(&self) -> [u8; 32] {
        self.datagram.root_key()
    }

    pub fn new_root_key() -> [u8; 32] {
        SecureDatagramSession::new_root_key()
    }

    pub fn next_sync_epoch(&self) -> u32 {
        self.datagram.next_sync_epoch()
    }

    pub fn prepare_sync_transition(&self) -> Result<(u32, [u8; 32], u32, u64), anyhow::Error> {
        self.prepare_sync_transition_at(None)
    }

    pub fn prepare_sync_transition_at(
        &self,
        requested_epoch: impl Into<Option<u32>>,
    ) -> Result<(u32, [u8; 32], u32, u64), anyhow::Error> {
        let mut transition = self.transition.lock().unwrap();
        if transition.pending_epoch.is_some() {
            return Err(anyhow!("session synchronization is already pending"));
        }
        let session_generation = self.datagram.session_generation();
        let root_key = self.datagram.root_key();
        let minimum_epoch = self
            .datagram
            .next_sync_epoch()
            .max(transition.reserved_epoch.wrapping_add(1));
        let next_epoch = match requested_epoch.into() {
            Some(epoch) if epoch < minimum_epoch => {
                return Err(anyhow!("session synchronization epoch is stale"));
            }
            Some(epoch) => epoch,
            None => minimum_epoch,
        };
        transition.reserved_epoch = next_epoch;
        transition.pending_epoch = Some(next_epoch);
        transition.revision = transition.revision.wrapping_add(1);
        Ok((
            session_generation,
            root_key,
            next_epoch,
            transition.revision,
        ))
    }

    pub fn commit_reserved_sync(
        &self,
        expected_revision: u64,
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        transition_id: [u8; 16],
    ) -> Result<(), anyhow::Error> {
        let mut transition = self.transition.lock().unwrap();
        if !self.is_valid() {
            return Err(anyhow!("session invalidated before synchronization commit"));
        }
        if transition.revision != expected_revision
            || transition.pending_epoch != Some(initial_epoch)
        {
            return Err(anyhow!("session changed before synchronization commit"));
        }
        self.datagram
            .sync_root_key(root_key, session_generation, initial_epoch, true);
        if let Some(peer_static_pubkey) = transition.pending_peer_static_pubkey.take() {
            *self.peer_static_pubkey.write().unwrap() = Some(peer_static_pubkey);
        }
        transition.committed_history.push_back(CommittedTransition {
            action: PeerSessionAction::Sync,
            session_generation,
            root_key,
            initial_epoch,
            transition_id,
            transition_revision: expected_revision,
        });
        while transition.committed_history.len() > MAX_COMMITTED_TRANSITIONS_PER_SESSION {
            transition.committed_history.pop_front();
        }
        transition.revision = transition.revision.wrapping_add(1);
        transition.reserved_epoch = transition.reserved_epoch.max(initial_epoch);
        transition.pending_epoch = None;
        Ok(())
    }

    pub fn cancel_reserved_sync(&self, expected_revision: u64, initial_epoch: u32) {
        let mut transition = self.transition.lock().unwrap();
        if transition.revision == expected_revision
            && transition.pending_epoch == Some(initial_epoch)
        {
            transition.pending_epoch = None;
            transition.pending_peer_static_pubkey = None;
            transition.reserved_epoch = self.datagram.next_sync_epoch().wrapping_sub(1);
            transition.revision = transition.revision.wrapping_add(1);
        }
    }

    pub fn transition_revision(&self) -> u64 {
        self.transition.lock().unwrap().revision
    }

    pub fn root_key_digest(&self) -> [u8; 32] {
        InitiatorTransitionIdentity::digest_root_key(&self.root_key())
    }

    fn record_committed_transition(
        &self,
        action: PeerSessionAction,
        session_generation: u32,
        root_key: [u8; 32],
        initial_epoch: u32,
        transition_id: [u8; 16],
        transition_revision: u64,
    ) {
        let mut transition = self.transition.lock().unwrap();
        transition.committed_history.push_back(CommittedTransition {
            action,
            session_generation,
            root_key,
            initial_epoch,
            transition_id,
            transition_revision,
        });
        while transition.committed_history.len() > MAX_COMMITTED_TRANSITIONS_PER_SESSION {
            transition.committed_history.pop_front();
        }
    }

    fn committed_transition(
        &self,
        identity: &InitiatorTransitionIdentity,
    ) -> Option<CommittedTransition> {
        self.transition
            .lock()
            .unwrap()
            .committed_history
            .iter()
            .rev()
            .copied()
            .find(|committed| {
                committed.action == identity.action
                    && committed.session_generation == identity.session_generation
                    && committed.initial_epoch == identity.initial_epoch
                    && committed.transition_id == identity.transition_id
                    && InitiatorTransitionIdentity::digest_root_key(&committed.root_key)
                        == identity.root_key_digest
            })
    }

    fn last_committed_transition(&self) -> Option<CommittedTransition> {
        self.transition
            .lock()
            .unwrap()
            .committed_history
            .back()
            .copied()
    }

    fn initialize_transition_revision(&self, revision: u64) {
        let mut transition = self.transition.lock().unwrap();
        debug_assert_eq!(transition.revision, 0);
        debug_assert!(transition.pending_epoch.is_none());
        transition.revision = revision;
    }

    pub fn has_pending_transition(&self) -> bool {
        self.transition.lock().unwrap().pending_epoch.is_some()
    }

    pub fn reserve_peer_static_pubkey(
        &self,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<(), anyhow::Error> {
        let Some(peer_static_pubkey) = peer_static_pubkey else {
            return Ok(());
        };
        let mut transition = self.transition.lock().unwrap();
        if let Some(existing) = *self.peer_static_pubkey.read().unwrap()
            && existing != peer_static_pubkey
        {
            return Err(anyhow!("peer static pubkey mismatch"));
        }
        if transition
            .pending_peer_static_pubkey
            .is_some_and(|pending| pending != peer_static_pubkey)
        {
            return Err(anyhow!("peer static pubkey transition is already pending"));
        }
        transition.pending_peer_static_pubkey = Some(peer_static_pubkey);
        Ok(())
    }

    pub fn commit_reserved_peer_static_pubkey(&self) -> Result<(), anyhow::Error> {
        let mut transition = self.transition.lock().unwrap();
        if let Some(peer_static_pubkey) = transition.pending_peer_static_pubkey {
            let mut current = self.peer_static_pubkey.write().unwrap();
            if current.is_some_and(|existing| existing != peer_static_pubkey) {
                return Err(anyhow!("peer static pubkey mismatch"));
            }
            *current = Some(peer_static_pubkey);
            transition.pending_peer_static_pubkey = None;
        }
        Ok(())
    }

    pub fn cancel_reserved_peer_static_pubkey(&self) {
        self.transition.lock().unwrap().pending_peer_static_pubkey = None;
    }

    pub fn invalidate_if_revision(&self, expected_revision: u64) -> bool {
        let mut transition = self.transition.lock().unwrap();
        if transition.revision != expected_revision {
            return false;
        }
        self.invalidated.store(true, Ordering::Relaxed);
        self.datagram.invalidate();
        transition.revision = transition.revision.wrapping_add(1);
        transition.pending_epoch = None;
        transition.pending_peer_static_pubkey = None;
        true
    }

    pub fn check_encrypt_algo_same(
        &self,
        send_algorithm: &str,
        recv_algorithm: &str,
    ) -> Result<(), anyhow::Error> {
        self.datagram
            .check_encrypt_algo_same(send_algorithm, recv_algorithm)
    }

    pub fn check_or_set_peer_static_pubkey(
        &self,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<(), anyhow::Error> {
        let Some(peer_static_pubkey) = peer_static_pubkey else {
            return Ok(());
        };
        let transition = self.transition.lock().unwrap();
        let mut guard = self.peer_static_pubkey.write().unwrap();
        if transition.pending_peer_static_pubkey.is_some() && guard.is_none() {
            return Err(anyhow!("peer static pubkey transition is pending"));
        }
        if let Some(existing) = *guard {
            if existing != peer_static_pubkey {
                return Err(anyhow!("peer static pubkey mismatch"));
            }
            return Ok(());
        }
        *guard = Some(peer_static_pubkey);
        Ok(())
    }

    pub fn check_peer_static_pubkey(
        &self,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<(), anyhow::Error> {
        let Some(peer_static_pubkey) = peer_static_pubkey else {
            return Ok(());
        };
        let transition = self.transition.lock().unwrap();
        let current = *self.peer_static_pubkey.read().unwrap();
        if current.is_some_and(|existing| existing != peer_static_pubkey)
            || transition
                .pending_peer_static_pubkey
                .is_some_and(|pending| pending != peer_static_pubkey)
        {
            return Err(anyhow!("peer static pubkey mismatch"));
        }
        Ok(())
    }

    pub fn peer_static_pubkey(&self) -> Option<[u8; 32]> {
        *self.peer_static_pubkey.read().unwrap()
    }

    pub fn peer_static_pubkey_with_pending(&self) -> Option<[u8; 32]> {
        let transition = self.transition.lock().unwrap();
        transition
            .pending_peer_static_pubkey
            .or_else(|| *self.peer_static_pubkey.read().unwrap())
    }

    pub fn sync_root_key(
        &self,
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        preserve_rx_grace: bool,
    ) {
        let mut transition = self.transition.lock().unwrap();
        self.datagram.sync_root_key(
            root_key,
            session_generation,
            initial_epoch,
            preserve_rx_grace,
        );
        transition.revision = transition.revision.wrapping_add(1);
        transition.reserved_epoch = transition.reserved_epoch.max(initial_epoch);
        transition.pending_epoch = None;
        transition.pending_peer_static_pubkey = None;
    }

    pub fn dir_for_sender(
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
    ) -> SecureDatagramDirection {
        if sender_peer_id < receiver_peer_id {
            SecureDatagramDirection::AToB
        } else {
            SecureDatagramDirection::BToA
        }
    }

    pub fn encrypt_payload(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        pkt: &mut ZCPacket,
    ) -> Result<(), anyhow::Error> {
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        self.datagram
            .encrypt_payload(Self::dir_for_sender(sender_peer_id, receiver_peer_id), pkt)
    }

    pub fn encrypt_payload_batch(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        packets: &mut [ZCPacket],
    ) -> Result<(), anyhow::Error> {
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        self.datagram.encrypt_payload_batch(
            Self::dir_for_sender(sender_peer_id, receiver_peer_id),
            packets,
        )
    }

    pub fn encrypt_fec_payload(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        pkt: &mut ZCPacket,
    ) -> Result<(), anyhow::Error> {
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        self.datagram
            .encrypt_fec_payload(Self::dir_for_sender(sender_peer_id, receiver_peer_id), pkt)
    }

    pub fn encrypt_fec_payload_batch(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        packets: &mut [ZCPacket],
    ) -> Result<(), anyhow::Error> {
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        self.datagram.encrypt_fec_payload_batch(
            Self::dir_for_sender(sender_peer_id, receiver_peer_id),
            packets,
        )
    }

    pub fn decrypt_payload(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        ciphertext_with_tail: &mut ZCPacket,
    ) -> Result<(), anyhow::Error> {
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        self.datagram.decrypt_payload(
            Self::dir_for_sender(sender_peer_id, receiver_peer_id),
            ciphertext_with_tail,
        )
    }

    pub fn decrypt_payload_batch(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        packets: &mut [ZCPacket],
    ) -> smallvec::SmallVec<[Result<(), anyhow::Error>; 64]> {
        if !self.is_valid() {
            return packets
                .iter()
                .map(|_| Err(anyhow!("session invalidated")))
                .collect();
        }
        self.datagram.decrypt_payload_batch(
            Self::dir_for_sender(sender_peer_id, receiver_peer_id),
            packets,
        )
    }

    pub fn decrypt_fec_payload(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        ciphertext_with_tail: &mut ZCPacket,
    ) -> Result<(), anyhow::Error> {
        if !self.is_valid() {
            return Err(anyhow!("session invalidated"));
        }
        self.datagram.decrypt_fec_payload(
            Self::dir_for_sender(sender_peer_id, receiver_peer_id),
            ciphertext_with_tail,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static IN_DOUBT_TEST_LOCK: Mutex<()> = Mutex::new(());
    static RECEIPT_TEST_LOCK: Mutex<()> = Mutex::new(());
    static RESPONDER_PROOF_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn responder_recovery_debug_output_redacts_the_root_key() {
        let root_key = [0xa5; 32];
        let recovery = ResponderTransitionRecovery {
            session: Arc::new(PeerSession::new(
                7,
                root_key,
                1,
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )),
            action: PeerSessionAction::Create,
            session_generation: 1,
            root_key,
            initial_epoch: 0,
            transition_id: [1; 16],
            transition_revision: 1,
        };

        let output = format!("{recovery:?}");
        assert!(!output.contains("165"));
        assert!(output.contains("root_key: <redacted>"));
    }

    #[test]
    fn concurrent_responder_creates_publish_only_one_session() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("test".to_string(), 7);
        let barrier = Arc::new(std::sync::Barrier::new(32));
        let mut threads = Vec::new();

        for _ in 0..32 {
            let store = store.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let Ok(prepared) = store.prepare_responder_session(
                    &key,
                    "aes-256-gcm".to_string(),
                    "aes-256-gcm".to_string(),
                    None,
                ) else {
                    return None;
                };
                let root_key = prepared.session.root_key();
                if !matches!(prepared.action, PeerSessionAction::Create) {
                    prepared.cancel();
                    return None;
                }
                if prepared
                    .session
                    .reserve_peer_static_pubkey(Some([0x13; 32]))
                    .is_err()
                {
                    prepared.cancel();
                    return None;
                }
                match store.commit_prepared_responder_transition(&key, &prepared) {
                    Ok(()) => Some(root_key),
                    Err(_) => {
                        prepared.cancel();
                        None
                    }
                }
            }));
        }

        let published_root_keys = threads
            .into_iter()
            .filter_map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(published_root_keys.len(), 1);
        assert_eq!(store.get(&key).unwrap().root_key(), published_root_keys[0]);
    }

    #[test]
    fn responder_create_claim_is_exclusive_until_commit_or_cancel() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("test".to_string(), 7);
        let first = store
            .prepare_responder_session(
                &key,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();

        assert!(matches!(first.action, PeerSessionAction::Create));
        assert!(
            store
                .prepare_responder_session(
                    &key,
                    "aes-256-gcm".to_string(),
                    "aes-256-gcm".to_string(),
                    None,
                )
                .is_err()
        );

        first.cancel();
        assert!(matches!(
            store
                .prepare_responder_session(
                    &key,
                    "aes-256-gcm".to_string(),
                    "aes-256-gcm".to_string(),
                    None,
                )
                .unwrap()
                .action,
            PeerSessionAction::Create
        ));
    }

    #[test]
    fn canceled_sync_reservation_does_not_consume_epochs() {
        let session = PeerSession::new(
            7,
            PeerSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
            None,
        );

        let (_, _, first_epoch, first_revision) = session.prepare_sync_transition().unwrap();
        assert!(session.prepare_sync_transition().is_err());
        session.cancel_reserved_sync(first_revision, first_epoch);

        let (_, _, second_epoch, second_revision) = session.prepare_sync_transition().unwrap();
        assert_eq!(second_epoch, first_epoch);
        assert_ne!(second_revision, first_revision);
        assert!(!session.invalidate_if_revision(first_revision));
    }

    #[test]
    fn initiator_create_stays_private_until_commit_and_cancel_releases_claim() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("test".to_string(), 9);
        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        assert!(store.peek(&key).is_none());
        assert!(
            store
                .prepare_initiator_action(
                    &key,
                    PeerSessionAction::Create,
                    1,
                    Some(PeerSession::new_root_key()),
                    0,
                    "aes-256-gcm".to_string(),
                    "aes-256-gcm".to_string(),
                    None,
                )
                .is_err()
        );
        reservation.cancel();
        assert!(store.peek(&key).is_none());

        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let expected = reservation.session();
        let committed = reservation.commit().unwrap();
        assert!(Arc::ptr_eq(&expected, &committed));
        assert!(
            store
                .peek(&key)
                .is_some_and(|active| Arc::ptr_eq(&active, &expected))
        );
    }

    #[test]
    fn initiator_sync_stages_keys_and_rejects_stale_timeout() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("test".to_string(), 10);
        let old_root = PeerSession::new_root_key();
        let session = Arc::new(PeerSession::new(
            key.peer_id,
            old_root,
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
            None,
        ));
        store.insert_session(key.clone(), session.clone());

        let first = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Sync,
                1,
                Some(PeerSession::new_root_key()),
                1,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let first_revision = first.transition_revision();
        assert_eq!(session.root_key(), old_root);
        first.cancel();

        let second_root = PeerSession::new_root_key();
        let second = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Sync,
                1,
                Some(second_root),
                1,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        assert_ne!(second.transition_revision(), first_revision);
        assert!(!session.invalidate_if_revision(first_revision));
        assert!(session.is_valid());
        second.commit().unwrap();
        assert_eq!(session.root_key(), second_root);
    }

    #[test]
    fn responder_static_key_is_published_only_at_sync_commit() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("test".to_string(), 11);
        let current = Arc::new(PeerSession::new(
            key.peer_id,
            PeerSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
            None,
        ));
        store.insert_session(key.clone(), current.clone());
        let static_key = [3_u8; 32];
        let prepared = store
            .prepare_responder_session(
                &key,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                Some(static_key),
            )
            .unwrap();
        assert_eq!(current.peer_static_pubkey(), None);
        store
            .commit_prepared_responder_transition(&key, &prepared)
            .unwrap();
        assert_eq!(current.peer_static_pubkey(), Some(static_key));
    }

    #[test]
    fn removing_old_session_cannot_remove_a_replacement() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("test".to_string(), 12);
        let old = Arc::new(PeerSession::new(
            key.peer_id,
            PeerSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
            None,
        ));
        let replacement = Arc::new(PeerSession::new(
            key.peer_id,
            PeerSession::new_root_key(),
            2,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
            None,
        ));
        store.insert_session(key.clone(), old.clone());
        old.invalidate();
        store.insert_session(key.clone(), replacement.clone());
        store.remove_if_same(&key, &old);
        assert!(
            store
                .peek(&key)
                .is_some_and(|current| Arc::ptr_eq(&current, &replacement))
        );
    }

    #[test]
    fn suspended_initiator_reservation_resumes_only_with_exact_identity() {
        let _test_guard = IN_DOUBT_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let key = SessionKey::new("test".to_string(), 13);
        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let expected = reservation.session();
        let responder_metadata = uuid::Uuid::new_v4();
        let identity = reservation.transition_identity_with_session_metadata(responder_metadata);
        reservation
            .suspend_with_session_metadata(responder_metadata, Duration::from_secs(1))
            .unwrap();
        assert_eq!(store.in_doubt_reservation_count(), 1);
        let mut mismatch = identity.clone();
        mismatch.transition_id[0] ^= 1;
        assert!(store.resume_initiator_reservation(&mismatch).is_err());
        assert_eq!(store.in_doubt_reservation_count(), 1);
        let resumed = store.resume_initiator_reservation(&identity).unwrap();
        assert!(Arc::ptr_eq(&resumed.session(), &expected));
        resumed.commit().unwrap();
        assert_eq!(store.in_doubt_reservation_count(), 0);
    }

    #[test]
    fn exact_recovery_static_key_check_reads_pending_key_without_consuming_state() {
        let _test_guard = IN_DOUBT_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let key = SessionKey::new("test".to_string(), 15);
        let session = Arc::new(PeerSession::new(
            key.peer_id,
            PeerSession::new_root_key(),
            1,
            0,
            "aes-256-gcm".to_string(),
            "aes-256-gcm".to_string(),
            None,
        ));
        store.insert_session(key.clone(), session);
        let expected_key = [0x52_u8; 32];
        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Sync,
                1,
                Some(PeerSession::new_root_key()),
                1,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                Some(expected_key),
            )
            .unwrap();
        let identity = reservation.transition_identity();
        reservation.suspend(Duration::from_secs(1)).unwrap();

        assert!(
            store
                .check_in_doubt_recovery_peer_static_pubkey(&identity, Some(expected_key))
                .unwrap()
        );
        assert!(
            !store
                .check_in_doubt_recovery_peer_static_pubkey(&identity, Some([0x53_u8; 32]))
                .unwrap()
        );
        assert!(
            !store
                .check_in_doubt_recovery_peer_static_pubkey(&identity, None)
                .unwrap()
        );
        assert_eq!(store.in_doubt_reservation_count(), 1);
        assert!(store.cancel_initiator_reservation_exact(&identity));
    }

    #[test]
    fn suspended_initiator_reservation_is_not_rolled_back_by_time() {
        let _test_guard = IN_DOUBT_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let key = SessionKey::new("test".to_string(), 14);
        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        reservation.suspend(Duration::from_millis(1)).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(store.expire_in_doubt_sessions(), 0);
        assert_eq!(store.in_doubt_reservation_count(), 1);
        assert!(store.peek(&key).is_none());
        assert!(
            store
                .prepare_initiator_action(
                    &key,
                    PeerSessionAction::Create,
                    1,
                    Some(PeerSession::new_root_key()),
                    0,
                    "aes-256-gcm".to_string(),
                    "aes-256-gcm".to_string(),
                    None,
                )
                .is_err()
        );
        let identity = store.in_doubt_identity(&key).unwrap();
        assert!(store.cancel_initiator_reservation_exact(&identity));
        assert_eq!(store.in_doubt_reservation_count(), 0);
    }

    #[test]
    fn active_responder_transition_reconciles_without_staging() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("test".to_string(), 15);
        let prepared = store
            .prepare_responder_session(
                &key,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        prepared
            .session
            .reserve_peer_static_pubkey(Some([0x11; 32]))
            .unwrap();
        let identity = InitiatorTransitionIdentity::new(
            key.clone(),
            prepared.session.metadata_session_id(),
            prepared.action,
            prepared.session_generation,
            prepared.initial_epoch,
            prepared.transition_id(),
            InitiatorTransitionIdentity::digest_root_key(
                &prepared.root_key.expect("CREATE has a root key"),
            ),
        );
        store
            .commit_prepared_responder_transition(&key, &prepared)
            .unwrap();
        let recovery = store
            .reconcile_active_responder_transition(&identity)
            .unwrap()
            .expect("exact active transition");
        assert!(Arc::ptr_eq(&recovery.session, &prepared.session));
        assert_eq!(recovery.action, PeerSessionAction::Create);
        assert_eq!(recovery.transition_id, identity.transition_id);
        assert_eq!(recovery.root_key, prepared.root_key.unwrap());
    }

    #[test]
    fn responder_proof_does_not_expire_before_authenticated_acknowledgement() {
        let _test_guard = RESPONDER_PROOF_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let key = SessionKey::new("expired-proof".to_string(), 151);
        let prepared = store
            .prepare_responder_session(
                &key,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        prepared
            .session
            .reserve_peer_static_pubkey(Some([0x12; 32]))
            .unwrap();
        let identity = InitiatorTransitionIdentity::new(
            key.clone(),
            prepared.session.metadata_session_id(),
            prepared.action,
            prepared.session_generation,
            prepared.initial_epoch,
            prepared.transition_id(),
            InitiatorTransitionIdentity::digest_root_key(&prepared.root_key.unwrap()),
        );
        store
            .commit_prepared_responder_transition(&key, &prepared)
            .unwrap();
        let before = RESPONDER_RECOVERY_RECORD_COUNT.load(Ordering::Acquire);

        {
            let _guard = store.creation_lock.lock().unwrap();
            assert_eq!(
                store.expire_responder_recoveries_locked(INITIATOR_RECOVERY_LIFETIME),
                0
            );
        }

        assert_eq!(
            RESPONDER_RECOVERY_RECORD_COUNT.load(Ordering::Acquire),
            before
        );
        assert!(store.has_responder_recovery(&key));
        assert!(
            store
                .reconcile_active_responder_transition(&identity)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn responder_recovery_proof_requires_exact_acknowledgement() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("proof".to_string(), 16);
        let prepared = store
            .prepare_responder_session(
                &key,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let transition_id = prepared.transition_id();
        prepared
            .session
            .reserve_peer_static_pubkey(Some([0x15; 32]))
            .unwrap();
        store
            .commit_prepared_responder_transition(&key, &prepared)
            .unwrap();
        assert!(!store.acknowledge_responder_recovery(&key, [1; 16]));
        assert!(store.responder_recoveries.contains_key(&key));
        assert!(store.acknowledge_responder_recovery(&key, transition_id));
        assert!(!store.responder_recoveries.contains_key(&key));
    }

    #[test]
    fn responder_recovery_dependency_survives_drop_until_authenticated_commit() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("proof-dependency".to_string(), 18);
        let first = store
            .prepare_responder_session(
                &key,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let old_id = first.transition_id();
        first
            .session
            .reserve_peer_static_pubkey(Some([0x16; 32]))
            .unwrap();
        store
            .commit_prepared_responder_transition(&key, &first)
            .unwrap();

        let staged = store
            .prepare_responder_session_with_recovery_proof(
                &key,
                old_id,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        assert_eq!(staged.proof_dependency(), Some(old_id));
        assert!(!staged.proof_dependency_cleared());
        assert!(
            store
                .commit_prepared_responder_transition(&key, &staged)
                .is_err()
        );
        staged.cancel();
        assert_eq!(store.responder_recovery_id(&key), Some(old_id));
        assert!(
            store
                .prepare_responder_session(
                    &key,
                    "aes-256-gcm".to_string(),
                    "aes-256-gcm".to_string(),
                    None
                )
                .is_err()
        );

        let staged = store
            .prepare_responder_session_with_recovery_proof(
                &key,
                old_id,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        assert!(staged.authenticate_recovery().is_ok());
        assert!(staged.proof_dependency_cleared());
        store
            .commit_prepared_responder_transition(&key, &staged)
            .unwrap();
        assert_ne!(store.responder_recovery_id(&key), Some(old_id));
    }

    #[test]
    fn initiator_receipt_pins_session_until_exact_acknowledgement() {
        let _test_guard = RECEIPT_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let key = SessionKey::new("receipt".to_string(), 17);
        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let session = reservation.commit().unwrap();
        let identity = reservation.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        store
            .record_initiator_receipt(identity.clone(), session.clone())
            .unwrap();
        drop(session);
        drop(reservation);
        store.evict_unused_sessions_idle(Duration::ZERO);
        assert!(store.peek(&key).is_some());
        assert_ne!(store.initiator_receipt_id(&key), Some([0; 16]));
        assert!(!store.acknowledge_initiator_receipt(&key, [9; 16]));
        assert!(store.acknowledge_initiator_receipt(&key, identity.transition_id));
        store.evict_unused_sessions_idle(Duration::ZERO);
        assert!(store.peek(&key).is_none());
    }

    #[test]
    fn verified_peer_removal_clears_lost_ack_receipt_only_for_matching_key() {
        let _test_guard = RECEIPT_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let key = SessionKey::new("receipt-removal".to_string(), 22);
        let peer_static_pubkey = [0xA5_u8; 32];
        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                Some(peer_static_pubkey),
            )
            .unwrap();
        let session = reservation.commit().unwrap();
        let identity = reservation.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        store
            .record_initiator_receipt(identity, session.clone())
            .unwrap();

        assert!(!store.clear_peer_records_if_static_key_matches(&key, [0x5A_u8; 32]));
        assert!(store.peek(&key).is_some());
        assert!(store.initiator_receipt_id(&key).is_some());

        assert!(store.clear_peer_records_if_static_key_matches(&key, peer_static_pubkey));
        assert!(store.peek(&key).is_none());
        assert!(store.initiator_receipt_id(&key).is_none());
        assert!(!session.is_valid());
    }

    #[test]
    fn initiator_receipt_conflict_does_not_publish_pending_create() {
        let _test_guard = RECEIPT_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let key = SessionKey::new("receipt-conflict".to_string(), 19);
        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let identity = reservation.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        store
            .record_initiator_receipt(identity.clone(), reservation.session())
            .unwrap();

        assert!(reservation.commit_with_receipt(identity.clone()).is_err());
        assert!(store.peek(&key).is_none());
        assert_eq!(
            store.initiator_receipt_identity(&key),
            Some(identity.clone())
        );
        assert!(store.acknowledge_initiator_receipt_exact(&identity));
    }

    #[test]
    fn initiator_receipt_quota_failure_does_not_publish_or_commit() {
        let _test_guard = RECEIPT_TEST_LOCK.lock().unwrap();
        let mut retained = Vec::with_capacity(MAX_INITIATOR_RECEIPT_RECORDS);
        for peer_id in 0..MAX_INITIATOR_RECEIPT_RECORDS as PeerId {
            let store = PeerSessionStore::new();
            let key = SessionKey::new("receipt-full".to_string(), peer_id);
            let root_key = PeerSession::new_root_key();
            let session = Arc::new(PeerSession::new(
                peer_id,
                root_key,
                1,
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            ));
            let transition_id = [(peer_id as u8) | 1; 16];
            let identity = InitiatorTransitionIdentity::new(
                key.clone(),
                uuid::Uuid::new_v4(),
                PeerSessionAction::Create,
                1,
                0,
                transition_id,
                InitiatorTransitionIdentity::digest_root_key(&root_key),
            );
            store
                .record_initiator_receipt(identity.clone(), session)
                .unwrap();
            retained.push((store, key, identity));
        }

        let store = PeerSessionStore::new();
        let key = SessionKey::new("receipt-full".to_string(), 1_000);
        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let identity = reservation.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        assert!(reservation.commit_with_receipt(identity).is_err());
        assert!(store.peek(&key).is_none());
        assert!(store.initiator_receipt_identity(&key).is_none());

        for (store, key, identity) in retained {
            assert!(store.acknowledge_initiator_receipt_exact(&identity));
            assert!(store.initiator_receipt_identity(&key).is_none());
        }
    }

    #[test]
    fn initiator_receipt_commit_failure_cleans_up_without_history() {
        let _test_guard = RECEIPT_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let key = SessionKey::new("receipt-failure".to_string(), 20);
        let reservation = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let session = reservation.session();
        let identity = reservation.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        session.invalidate();
        assert!(reservation.commit_with_receipt(identity).is_err());
        assert!(store.peek(&key).is_none());
        assert!(store.initiator_receipt_identity(&key).is_none());
        assert!(session.last_committed_transition().is_none());
    }

    #[test]
    fn initiator_receipt_replacement_restores_previous_receipt_on_failure() {
        let _test_guard = RECEIPT_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let key = SessionKey::new("receipt-replacement".to_string(), 21);
        let first = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let first_metadata = uuid::Uuid::new_v4();
        let first_identity = first.transition_identity_with_session_metadata(first_metadata);
        let session = first.commit().unwrap();
        store
            .record_initiator_receipt(first_identity.clone(), session.clone())
            .unwrap();

        let second_root = PeerSession::new_root_key();
        let second = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Sync,
                1,
                Some(second_root),
                session.next_sync_epoch(),
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let second_identity =
            second.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        second
            .commit_with_receipt_replacing(second_identity.clone(), Some(first_identity.clone()))
            .unwrap();
        assert_eq!(
            store.initiator_receipt_identity(&key),
            Some(second_identity.clone())
        );

        let third = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Sync,
                1,
                Some(PeerSession::new_root_key()),
                session.next_sync_epoch(),
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let third_identity = third.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        session.invalidate();
        assert!(
            third
                .commit_with_receipt_replacing(third_identity, Some(second_identity.clone()),)
                .is_err()
        );
        assert_eq!(
            store.initiator_receipt_identity(&key),
            Some(second_identity.clone())
        );
        assert!(store.acknowledge_initiator_receipt_exact(&second_identity));
    }

    #[test]
    fn initiator_receipt_replacement_allows_prior_ack_race() {
        let _test_guard = RECEIPT_TEST_LOCK.lock().unwrap();
        let baseline = INITIATOR_RECEIPT_RECORD_COUNT.load(Ordering::Acquire);
        let store = PeerSessionStore::new();
        let key = SessionKey::new("receipt-ack-race".to_string(), 23);
        let first = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let first_identity = first.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        let session = first.commit().unwrap();
        store
            .record_initiator_receipt(first_identity.clone(), session.clone())
            .unwrap();
        assert_eq!(
            INITIATOR_RECEIPT_RECORD_COUNT.load(Ordering::Acquire),
            baseline + 1
        );

        // Snapshot the prior receipt by preparing the next transition first,
        // then model its original authenticated ReadyReceiptAck arriving before
        // the new transition commits.
        let second = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Sync,
                1,
                Some(PeerSession::new_root_key()),
                session.next_sync_epoch(),
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let second_identity =
            second.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        assert!(store.acknowledge_initiator_receipt_exact(&first_identity));
        assert_eq!(
            INITIATOR_RECEIPT_RECORD_COUNT.load(Ordering::Acquire),
            baseline
        );

        second
            .commit_with_receipt_replacing(second_identity.clone(), Some(first_identity))
            .unwrap();
        assert_eq!(
            store.initiator_receipt_identity(&key),
            Some(second_identity.clone())
        );
        assert_eq!(
            INITIATOR_RECEIPT_RECORD_COUNT.load(Ordering::Acquire),
            baseline + 1
        );
        assert!(store.acknowledge_initiator_receipt_exact(&second_identity));
        assert_eq!(
            INITIATOR_RECEIPT_RECORD_COUNT.load(Ordering::Acquire),
            baseline
        );
    }

    #[test]
    fn initiator_receipt_replacement_rejects_competing_receipt() {
        let _test_guard = RECEIPT_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let key = SessionKey::new("receipt-competing-race".to_string(), 24);
        let first = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let first_identity = first.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        let session = first.commit().unwrap();
        store
            .record_initiator_receipt(first_identity.clone(), session.clone())
            .unwrap();

        let second = store
            .prepare_initiator_action(
                &key,
                PeerSessionAction::Sync,
                1,
                Some(PeerSession::new_root_key()),
                session.next_sync_epoch(),
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let second_identity =
            second.transition_identity_with_session_metadata(uuid::Uuid::new_v4());
        assert!(store.acknowledge_initiator_receipt_exact(&first_identity));

        let mut competing_identity = first_identity.clone();
        competing_identity.transition_id = [0xA5; 16];
        store
            .record_initiator_receipt(competing_identity.clone(), session.clone())
            .unwrap();
        assert!(
            second
                .commit_with_receipt_replacing(second_identity, Some(first_identity))
                .is_err()
        );
        assert_eq!(
            store.initiator_receipt_identity(&key),
            Some(competing_identity.clone())
        );
        assert!(store.acknowledge_initiator_receipt_exact(&competing_identity));
    }

    #[test]
    fn responder_proof_replacement_reuses_quota_at_global_limit() {
        let _test_guard = RESPONDER_PROOF_TEST_LOCK.lock().unwrap();
        let mut retained = Vec::with_capacity(MAX_RESPONDER_RECOVERY_RECORDS);
        while RESPONDER_RECOVERY_RECORD_COUNT.load(Ordering::Acquire)
            < MAX_RESPONDER_RECOVERY_RECORDS
        {
            let peer_id = retained.len() as PeerId + 2_000;
            let store = PeerSessionStore::new();
            let key = SessionKey::new("proof-full".to_string(), peer_id);
            let prepared = store
                .prepare_responder_session(
                    &key,
                    "aes-256-gcm".to_string(),
                    "aes-256-gcm".to_string(),
                    None,
                )
                .unwrap();
            let transition_id = prepared.transition_id();
            prepared
                .session
                .reserve_peer_static_pubkey(Some([0x14; 32]))
                .unwrap();
            store
                .commit_prepared_responder_transition(&key, &prepared)
                .unwrap();
            retained.push((store, key, transition_id));
        }
        assert_eq!(
            RESPONDER_RECOVERY_RECORD_COUNT.load(Ordering::Acquire),
            MAX_RESPONDER_RECOVERY_RECORDS
        );

        let (target_store, target_key, old_id) = {
            let (store, key, transition_id) = retained.first().unwrap();
            (store.clone(), key.clone(), *transition_id)
        };
        let staged = target_store
            .prepare_responder_session_with_recovery_proof(
                &target_key,
                old_id,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        staged.authenticate_recovery().unwrap();
        target_store
            .commit_prepared_responder_transition(&target_key, &staged)
            .unwrap();
        assert_eq!(
            RESPONDER_RECOVERY_RECORD_COUNT.load(Ordering::Acquire),
            MAX_RESPONDER_RECOVERY_RECORDS
        );
        let replacement_id = target_store.responder_recovery_id(&target_key).unwrap();
        assert_ne!(replacement_id, old_id);
        retained[0].2 = replacement_id;

        let failed = target_store
            .prepare_responder_session_with_recovery_proof(
                &target_key,
                replacement_id,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        failed.authenticate_recovery().unwrap();
        failed.session.invalidate();
        assert!(
            target_store
                .commit_prepared_responder_transition(&target_key, &failed)
                .is_err()
        );
        failed.cancel();
        drop(failed);
        assert_eq!(
            target_store.responder_recovery_id(&target_key),
            Some(replacement_id)
        );
        assert_eq!(
            RESPONDER_RECOVERY_RECORD_COUNT.load(Ordering::Acquire),
            MAX_RESPONDER_RECOVERY_RECORDS
        );

        for (store, key, transition_id) in retained {
            assert!(store.acknowledge_responder_recovery(&key, transition_id));
        }
    }

    #[test]
    fn in_doubt_reservations_have_a_global_capacity_bound() {
        let _test_guard = IN_DOUBT_TEST_LOCK.lock().unwrap();
        let store = PeerSessionStore::new();
        let mut identities = Vec::with_capacity(MAX_IN_DOUBT_RESERVATIONS);
        for peer_id in 0..MAX_IN_DOUBT_RESERVATIONS as PeerId {
            let key = SessionKey::new("capacity".to_string(), peer_id);
            let reservation = store
                .prepare_initiator_action(
                    &key,
                    PeerSessionAction::Create,
                    1,
                    Some(PeerSession::new_root_key()),
                    0,
                    "aes-256-gcm".to_string(),
                    "aes-256-gcm".to_string(),
                    None,
                )
                .unwrap();
            let identity = reservation.transition_identity();
            reservation.suspend(Duration::from_secs(1)).unwrap();
            identities.push(identity);
        }
        assert_eq!(
            store.in_doubt_reservation_count(),
            MAX_IN_DOUBT_RESERVATIONS
        );
        let key = SessionKey::new("capacity".to_string(), MAX_IN_DOUBT_RESERVATIONS as PeerId);
        assert!(
            store
                .prepare_initiator_action(
                    &key,
                    PeerSessionAction::Create,
                    1,
                    Some(PeerSession::new_root_key()),
                    0,
                    "aes-256-gcm".to_string(),
                    "aes-256-gcm".to_string(),
                    None,
                )
                .is_err()
        );
        assert_eq!(
            store.in_doubt_reservation_count(),
            MAX_IN_DOUBT_RESERVATIONS
        );
        // An exact authenticated reset releases one permit before a new
        // transition reserves recovery state.
        let released = identities.remove(0);
        assert!(store.cancel_initiator_reservation_exact(&released));
        let reset_key = SessionKey::new("capacity-reset".to_string(), 1);
        let reset_reservation = store
            .prepare_initiator_action(
                &reset_key,
                PeerSessionAction::Create,
                1,
                Some(PeerSession::new_root_key()),
                0,
                "aes-256-gcm".to_string(),
                "aes-256-gcm".to_string(),
                None,
            )
            .unwrap();
        let reset_identity = reset_reservation.transition_identity();
        reset_reservation.suspend(Duration::from_secs(1)).unwrap();
        assert_eq!(
            store.in_doubt_reservation_count(),
            MAX_IN_DOUBT_RESERVATIONS
        );
        assert!(store.cancel_initiator_reservation_exact(&reset_identity));
        for identity in identities {
            assert!(store.cancel_initiator_reservation_exact(&identity));
        }
        assert_eq!(store.in_doubt_reservation_count(), 0);
    }

    #[test]
    fn peer_session_supports_asymmetric_algorithms() {
        let a: PeerId = 10;
        let b: PeerId = 20;
        let root_key = PeerSession::new_root_key();
        let generation = 1u32;
        let initial_epoch = 0u32;

        let sa = PeerSession::new(
            b,
            root_key,
            generation,
            initial_epoch,
            "aes-256-gcm".to_string(),
            "chacha20-poly1305".to_string(),
            None,
        );
        let sb = PeerSession::new(
            a,
            root_key,
            generation,
            initial_epoch,
            "chacha20-poly1305".to_string(),
            "aes-256-gcm".to_string(),
            None,
        );

        let plaintext1 = b"hello from a";
        let mut pkt1 = ZCPacket::new_with_payload(plaintext1);
        pkt1.fill_peer_manager_hdr(a as u32, b as u32, 0);
        sa.encrypt_payload(a, b, &mut pkt1).unwrap();
        sb.decrypt_payload(a, b, &mut pkt1).unwrap();
        assert_eq!(pkt1.payload(), plaintext1);

        let plaintext2 = b"hello from b";
        let mut pkt2 = ZCPacket::new_with_payload(plaintext2);
        pkt2.fill_peer_manager_hdr(b as u32, a as u32, 0);
        sb.encrypt_payload(b, a, &mut pkt2).unwrap();
        sa.decrypt_payload(b, a, &mut pkt2).unwrap();
        assert_eq!(pkt2.payload(), plaintext2);
    }

    #[test]
    fn sync_root_key_preserves_generic_grace_window_constant() {
        assert_eq!(
            PeerSession::SYNC_RX_GRACE_AFTER_MS,
            SecureDatagramSession::SYNC_RX_GRACE_AFTER_MS
        );
    }

    #[test]
    fn peer_session_store_keeps_recent_session_without_external_refs() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("net".to_string(), 20);
        let session = Arc::new(PeerSession::new(
            20,
            PeerSession::new_root_key(),
            1,
            0,
            "aes-gcm".to_string(),
            "aes-gcm".to_string(),
            None,
        ));
        store.insert_session(key.clone(), session);

        assert!(store.get(&key).is_some());
        store.evict_unused_sessions();

        assert!(
            store.get(&key).is_some(),
            "recent relay sessions should survive the periodic GC"
        );
    }

    #[test]
    fn peer_session_store_evicts_idle_session_without_external_refs() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("net".to_string(), 20);
        let session = Arc::new(PeerSession::new(
            20,
            PeerSession::new_root_key(),
            1,
            0,
            "aes-gcm".to_string(),
            "aes-gcm".to_string(),
            None,
        ));
        store.insert_session(key.clone(), session);

        store.evict_unused_sessions_idle(Duration::from_millis(0));

        assert!(
            store.get(&key).is_none(),
            "idle sessions without external users should still be collected"
        );
    }

    #[test]
    fn peer_session_store_evicts_invalid_recent_session() {
        let store = PeerSessionStore::new();
        let key = SessionKey::new("net".to_string(), 20);
        let session = Arc::new(PeerSession::new(
            20,
            PeerSession::new_root_key(),
            1,
            0,
            "aes-gcm".to_string(),
            "aes-gcm".to_string(),
            None,
        ));
        store.insert_session(key.clone(), session);

        let session = store.get(&key).unwrap();
        session.invalidate();
        drop(session);
        store.evict_unused_sessions();

        assert!(
            !store.sessions.contains_key(&key),
            "invalid sessions should not be kept by recent activity"
        );
    }
}
