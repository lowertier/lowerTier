//! Partial DATAGRAM frames own bounded storage and expire while the connection is idle.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::Arc,
    task::Context,
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::time::{Instant, Sleep};

use super::{DecodedDatagram, ZCPacket, ZCPacketType, decode_quic_datagram_parts};
use crate::common::global_ctx::{
    ProcessMemoryGovernor, ProcessMemoryPermit, global_process_memory_governor,
};

// Reassembly shares the receive-lane byte ceiling. It cannot grow with fragment count alone.
const RETAINED_BYTES_LIMIT: usize = super::QUIC_DATAGRAM_RECEIVE_BUFFER_BYTES;
const ASSEMBLY_LIFETIME: Duration = Duration::from_secs(15);

struct FragmentInProgress {
    parts: Box<[Option<Bytes>]>,
    filled: usize,
    payload_bytes: usize,
    retained_bytes: usize,
    expires: Instant,
    permit: ProcessMemoryPermit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn reassembly_accepts_reordering_and_ignores_duplicates() {
        let governor = Arc::new(ProcessMemoryGovernor::with_limit(RETAINED_BYTES_LIMIT * 2));
        let mut fragments = DatagramFragments::with_governor(governor.clone());
        let now = Instant::now();
        let mut original = ZCPacket::new_with_payload(&[0x5a; 2000]);
        original.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);
        let expected = original.tunnel_payload().to_vec();
        let split = 1000;
        assert!(
            fragments
                .push_fragment(7, 1, 2, Bytes::copy_from_slice(&expected[split..]), now)
                .is_none()
        );
        let retained = governor.retained();
        assert!(
            fragments
                .push_fragment(7, 1, 2, Bytes::from_static(b"duplicate"), now)
                .is_none()
        );
        assert!(
            fragments
                .push_fragment(7, 0, 3, Bytes::from_static(b"wrong count"), now)
                .is_none()
        );
        assert_eq!(governor.retained(), retained);
        let result = fragments
            .push_fragment(7, 0, 2, Bytes::copy_from_slice(&expected[..split]), now)
            .unwrap();
        assert_eq!(result.tunnel_payload(), expected);
        assert_eq!(fragments.retained_bytes, 0);
        assert_eq!(governor.retained(), 0);
    }

    #[tokio::test]
    async fn fragment_slices_do_not_pin_receive_slabs() {
        struct Owner {
            bytes: Vec<u8>,
            dropped: Arc<AtomicBool>,
        }
        impl AsRef<[u8]> for Owner {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Relaxed);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let slab = Bytes::from_owner(Owner {
            bytes: vec![0x5a; 65536],
            dropped: dropped.clone(),
        });
        let slice = slab.slice(..64);
        drop(slab);
        let governor = Arc::new(ProcessMemoryGovernor::with_limit(4096));
        let mut fragments = DatagramFragments::with_governor(governor.clone());
        assert!(
            fragments
                .push_fragment(1, 0, 2, slice, Instant::now())
                .is_none()
        );
        assert!(dropped.load(Ordering::Relaxed));
        assert_eq!(
            governor.retained(),
            64 + 2 * std::mem::size_of::<Option<Bytes>>()
        );
        drop(fragments);
        assert_eq!(governor.retained(), 0);
    }

    #[tokio::test]
    async fn incomplete_fragments_expire_without_new_datagrams() {
        let governor = Arc::new(ProcessMemoryGovernor::with_limit(4096));
        let mut fragments = DatagramFragments::with_governor(governor.clone());
        let now = Instant::now();
        fragments.push_fragment(1, 0, 2, Bytes::from_static(b"partial"), now);
        fragments.pending.get_mut(&1).unwrap().expires = now + Duration::from_millis(5);
        fragments.schedule_expiry();
        tokio::time::timeout(
            Duration::from_secs(1),
            futures::future::poll_fn(|cx| {
                fragments.poll_expiry(cx);
                if fragments.pending.is_empty() {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(governor.retained(), 0);
    }

    #[tokio::test]
    async fn fragment_storage_obeys_connection_and_process_budgets() {
        let governor = Arc::new(ProcessMemoryGovernor::with_limit(RETAINED_BYTES_LIMIT * 2));
        let mut fragments = DatagramFragments::with_governor(governor.clone());
        let now = Instant::now();
        let half = RETAINED_BYTES_LIMIT / 2;
        fragments.push_fragment(1, 0, 3, Bytes::from(vec![0; half]), now);
        assert!(
            fragments
                .push_fragment(1, 1, 3, Bytes::from(vec![0; half]), now)
                .is_none()
        );
        assert!(fragments.pending.is_empty());
        assert_eq!(governor.retained(), 0);

        let governor = Arc::new(ProcessMemoryGovernor::with_limit(256));
        let mut a = DatagramFragments::with_governor(governor.clone());
        let mut b = DatagramFragments::with_governor(governor.clone());
        a.push_fragment(1, 0, 2, Bytes::from(vec![0; 100]), now);
        let retained = governor.retained();
        b.push_fragment(2, 0, 2, Bytes::from(vec![0; 100]), now);
        assert!(b.pending.is_empty());
        assert_eq!(governor.retained(), retained);
        a.expire(now + ASSEMBLY_LIFETIME);
        assert_eq!(governor.retained(), 0);
    }

    #[tokio::test]
    async fn fragment_count_eviction_and_assembly_failure_release_permits() {
        let governor = Arc::new(ProcessMemoryGovernor::with_limit(RETAINED_BYTES_LIMIT));
        let mut fragments = DatagramFragments::with_governor(governor.clone());
        let now = Instant::now();
        for id in 0..=super::super::DATAGRAM_FRAGMENT_MAX_PENDING as u32 {
            fragments.push_fragment(id, 0, 2, Bytes::from_static(b"part"), now);
        }
        assert_eq!(
            fragments.pending.len(),
            super::super::DATAGRAM_FRAGMENT_MAX_PENDING
        );
        assert!(!fragments.pending.contains_key(&0));
        drop(fragments);
        assert_eq!(governor.retained(), 0);

        let size = 2 * std::mem::size_of::<Option<Bytes>>() + 128;
        let governor = Arc::new(ProcessMemoryGovernor::with_limit(size));
        let mut fragments = DatagramFragments::with_governor(governor.clone());
        fragments.push_fragment(1, 0, 2, Bytes::from(vec![0; 64]), now);
        assert!(
            fragments
                .push_fragment(1, 1, 2, Bytes::from(vec![0; 64]), now)
                .is_none()
        );
        assert_eq!(governor.retained(), 0);
    }

    #[tokio::test]
    async fn incomplete_fragment_pressure_stays_bounded() {
        for payload_bytes in [64, 512, 1200] {
            let governor = Arc::new(ProcessMemoryGovernor::with_limit(RETAINED_BYTES_LIMIT * 2));
            let mut fragments = DatagramFragments::with_governor(governor.clone());
            let now = Instant::now();
            let payload = Bytes::from(vec![0x5a; payload_bytes]);
            let mut peak = 0;
            // Leave all 64 assemblies incomplete while each receives more fragments.
            for index in 0..254 {
                for id in 0..64 {
                    assert!(
                        fragments
                            .push_fragment(id, index, 255, payload.clone(), now)
                            .is_none()
                    );
                    peak = peak.max(governor.retained());
                    assert_eq!(governor.retained(), fragments.retained_bytes);
                    assert!(peak <= RETAINED_BYTES_LIMIT);
                }
            }
            let before_expiry = governor.retained();
            fragments.expire(now + ASSEMBLY_LIFETIME);
            assert_eq!(governor.retained(), 0);
            println!(
                "fragment_pressure payload_bytes={payload_bytes} inputs={} peak_owned_bytes={peak} before_expiry_bytes={before_expiry} after_expiry_bytes=0",
                64 * 254
            );
        }
    }
}

pub(super) struct DatagramFragments {
    pending: HashMap<u32, FragmentInProgress>,
    order: VecDeque<u32>,
    retained_bytes: usize,
    governor: Arc<ProcessMemoryGovernor>,
    expiry: Option<Pin<Box<Sleep>>>,
}

impl DatagramFragments {
    pub(super) fn new() -> Self {
        Self::with_governor(global_process_memory_governor())
    }

    fn with_governor(governor: Arc<ProcessMemoryGovernor>) -> Self {
        Self {
            pending: HashMap::new(),
            order: VecDeque::new(),
            retained_bytes: 0,
            governor,
            expiry: None,
        }
    }

    fn remove(&mut self, id: u32) -> Option<FragmentInProgress> {
        let entry = self.pending.remove(&id)?;
        self.retained_bytes -= entry.retained_bytes;
        self.order.retain(|pending_id| *pending_id != id);
        Some(entry)
    }

    fn schedule_expiry(&mut self) {
        let Some(entry) = self.order.front().and_then(|id| self.pending.get(id)) else {
            return;
        };
        if let Some(timer) = &mut self.expiry {
            timer.as_mut().reset(entry.expires);
        } else {
            self.expiry = Some(Box::pin(tokio::time::sleep_until(entry.expires)));
        }
    }

    fn expire(&mut self, now: Instant) {
        while let Some(id) = self.order.front().copied() {
            if self.pending[&id].expires > now {
                break;
            }
            self.remove(id);
        }
        self.schedule_expiry();
    }

    pub(super) fn poll_expiry(&mut self, cx: &mut Context<'_>) {
        if !self.pending.is_empty()
            && self
                .expiry
                .as_mut()
                .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
        {
            self.expire(Instant::now());
        }
    }

    pub(super) fn ingest(&mut self, bytes: Bytes, stream_id: u64) -> Option<ZCPacket> {
        match decode_quic_datagram_parts(bytes, stream_id) {
            Ok(DecodedDatagram::Whole(packet)) => Some(packet),
            Ok(DecodedDatagram::Fragment {
                id,
                index,
                count,
                payload,
            }) => {
                let packet = self.push_fragment(id, index, count, payload, Instant::now());
                self.schedule_expiry();
                packet
            }
            Err(error) => {
                tracing::debug!(?error, "dropping malformed QUIC DATAGRAM");
                None
            }
        }
    }

    fn push_fragment(
        &mut self,
        id: u32,
        index: u8,
        count: u8,
        payload: Bytes,
        now: Instant,
    ) -> Option<ZCPacket> {
        if count == 0 || index >= count {
            return None;
        }
        self.expire(now);
        if let Some(entry) = self.pending.get(&id) {
            if entry.parts.len() != usize::from(count) || entry.parts[usize::from(index)].is_some()
            {
                return None;
            }
        }
        let metadata_bytes = if self.pending.contains_key(&id) {
            0
        } else {
            usize::from(count) * std::mem::size_of::<Option<Bytes>>()
        };
        let charge = metadata_bytes.checked_add(payload.len())?;
        if charge > RETAINED_BYTES_LIMIT.saturating_sub(self.retained_bytes) {
            self.remove(id);
            return None;
        }
        if !self.pending.contains_key(&id) {
            if self.pending.len() == super::DATAGRAM_FRAGMENT_MAX_PENDING {
                self.remove(
                    *self
                        .order
                        .front()
                        .expect("a full fragment cache has an oldest entry"),
                );
            }
            let permit = self.governor.try_reserve_owned(metadata_bytes)?;
            self.pending.insert(
                id,
                FragmentInProgress {
                    parts: vec![None; usize::from(count)].into_boxed_slice(),
                    filled: 0,
                    payload_bytes: 0,
                    retained_bytes: metadata_bytes,
                    expires: now + ASSEMBLY_LIFETIME,
                    permit,
                },
            );
            self.order.push_back(id);
            self.retained_bytes += metadata_bytes;
        }
        let entry = self.pending.get_mut(&id).unwrap();
        if !entry.permit.try_extend(payload.len()) {
            self.remove(id);
            return None;
        }
        // A small slice can pin a complete QUIC receive slab. Own only the retained bytes.
        entry.parts[usize::from(index)] = Some(Bytes::copy_from_slice(&payload));
        entry.filled += 1;
        entry.payload_bytes += payload.len();
        entry.retained_bytes += payload.len();
        self.retained_bytes += payload.len();
        if entry.filled != entry.parts.len() {
            return None;
        }

        let assembled = self.remove(id)?;
        if assembled.payload_bytes < super::PEER_MANAGER_HEADER_SIZE {
            return None;
        }
        // Reserve the assembly peak, then allocate once instead of growing while copying parts.
        let _output_permit = self.governor.try_reserve_owned(assembled.payload_bytes)?;
        let mut payload = BytesMut::with_capacity(assembled.payload_bytes);
        for part in assembled.parts.into_vec() {
            payload.extend_from_slice(&part?);
        }
        Some(ZCPacket::new_from_buf(payload, ZCPacketType::DummyTunnel))
    }
}
