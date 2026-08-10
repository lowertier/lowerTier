use std::{
    ops::{Deref, DerefMut},
    slice,
    sync::OnceLock,
};

use rayon::prelude::*;
use smallvec::{IntoIter, SmallVec};

use super::packet_def::ZCPacket;

/// Maximum number of packets carried by one scheduling and I/O batch.
///
/// This matches the existing Darwin utun vector width. A batch never waits to
/// reach this size; producers append only packets that are already available.
pub const MAX_PACKET_BATCH_SIZE: usize = 64;
pub const PARALLEL_CRYPTO_MIN_BATCH_SIZE: usize = 32;

static PARALLEL_CRYPTO_ENABLED: OnceLock<bool> = OnceLock::new();

fn parallel_crypto_configured(
    batch_size: usize,
    explicitly_enabled: bool,
    explicitly_disabled: bool,
) -> bool {
    explicitly_enabled && batch_size >= PARALLEL_CRYPTO_MIN_BATCH_SIZE && !explicitly_disabled
}

pub fn parallel_crypto_enabled(batch_size: usize) -> bool {
    let enabled = *PARALLEL_CRYPTO_ENABLED.get_or_init(|| {
        std::env::var_os("EASYTIER_ENABLE_PARALLEL_CRYPTO").is_some()
            && std::env::var_os("EASYTIER_DEBUG_DISABLE_PARALLEL_CRYPTO").is_none()
    });
    parallel_crypto_configured(batch_size, enabled, false)
}

/// Runs independent packet work in parallel while retaining the owning
/// vector and its original packet order. Rayon may finish entries in any
/// order, but each worker mutates only its existing indexed slot.
pub fn ordered_parallel_try_for_each<T, E, F>(items: &mut [T], operation: F) -> Result<(), E>
where
    T: Send,
    E: Send,
    F: Fn(&mut T) -> Result<(), E> + Sync + Send,
{
    items.par_iter_mut().try_for_each(operation)
}

/// A bounded, owning packet vector.
///
/// Packets keep their existing `BytesMut` storage when moved into and out of a
/// batch. The type intentionally exposes no unbounded `push` operation.
#[derive(Debug)]
pub struct PacketBatch {
    packets: SmallVec<[ZCPacket; 4]>,
}

impl PacketBatch {
    pub fn new() -> Self {
        Self {
            packets: SmallVec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            packets: SmallVec::with_capacity(capacity.min(MAX_PACKET_BATCH_SIZE)),
        }
    }

    pub fn singleton(packet: ZCPacket) -> Self {
        Self {
            packets: smallvec::smallvec![packet],
        }
    }

    pub fn pop_singleton(mut self) -> Result<ZCPacket, Self> {
        if self.packets.len() != 1 {
            return Err(self);
        }
        Ok(self.packets.pop().expect("the packet batch has one entry"))
    }

    pub fn try_push(&mut self, packet: ZCPacket) -> Result<(), ZCPacket> {
        if self.packets.len() == MAX_PACKET_BATCH_SIZE {
            return Err(packet);
        }
        self.packets.push(packet);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Logical payload bytes in this batch, excluding reserved headroom.
    pub fn byte_len(&self) -> usize {
        self.packets.iter().map(ZCPacket::payload_len).sum()
    }

    /// Backing-buffer bytes, including headers and reserved prefix space.
    pub fn buffer_byte_len(&self) -> usize {
        self.packets.iter().map(ZCPacket::buf_len).sum()
    }

    pub fn iter(&self) -> slice::Iter<'_, ZCPacket> {
        self.packets.iter()
    }

    pub fn iter_mut(&mut self) -> slice::IterMut<'_, ZCPacket> {
        self.packets.iter_mut()
    }
}

impl Default for PacketBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for PacketBatch {
    type Target = [ZCPacket];

    fn deref(&self) -> &Self::Target {
        &self.packets
    }
}

impl DerefMut for PacketBatch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.packets
    }
}

impl IntoIterator for PacketBatch {
    type Item = ZCPacket;
    type IntoIter = IntoIter<[ZCPacket; 4]>;

    fn into_iter(self) -> Self::IntoIter {
        self.packets.into_iter()
    }
}

impl<'a> IntoIterator for &'a PacketBatch {
    type Item = &'a ZCPacket;
    type IntoIter = slice::Iter<'a, ZCPacket>;

    fn into_iter(self) -> Self::IntoIter {
        self.packets.iter()
    }
}

impl<'a> IntoIterator for &'a mut PacketBatch {
    type Item = &'a mut ZCPacket;
    type IntoIter = slice::IterMut<'a, ZCPacket>;

    fn into_iter(self) -> Self::IntoIter {
        self.packets.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        PARALLEL_CRYPTO_MIN_BATCH_SIZE, ordered_parallel_try_for_each, parallel_crypto_configured,
    };

    #[test]
    fn parallel_crypto_is_opt_in_for_large_vectors_and_can_be_disabled() {
        assert!(!parallel_crypto_configured(
            PARALLEL_CRYPTO_MIN_BATCH_SIZE,
            false,
            false
        ));
        assert!(!parallel_crypto_configured(
            PARALLEL_CRYPTO_MIN_BATCH_SIZE - 1,
            true,
            false
        ));
        assert!(parallel_crypto_configured(
            PARALLEL_CRYPTO_MIN_BATCH_SIZE,
            true,
            false
        ));
        assert!(!parallel_crypto_configured(
            PARALLEL_CRYPTO_MIN_BATCH_SIZE,
            true,
            true
        ));
    }

    #[test]
    fn ordered_parallel_work_keeps_vector_order_when_completion_reverses() {
        let mut values = (0_u8..8).collect::<Vec<_>>();

        ordered_parallel_try_for_each(&mut values, |value| {
            std::thread::sleep(Duration::from_millis((7 - *value) as u64));
            *value += 10;
            Ok::<_, ()>(())
        })
        .unwrap();

        assert_eq!(values, (10_u8..18).collect::<Vec<_>>());
    }
}
