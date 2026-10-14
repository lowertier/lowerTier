use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::Connection;
use crate::{
    DatagramReceiveDropPolicy, Instant, TransportError,
    frame::{Datagram, FrameStruct},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

fn queue_byte_limit(rate: f64, target: std::time::Duration, mtu: u16, hard_limit: usize) -> usize {
    ((rate * target.as_secs_f64()) as usize)
        .max(3 * 64 * usize::from(mtu))
        .min(hard_limit)
}

impl Datagrams<'_> {
    /// Age admission rate samples before sending a batch after an idle period.
    pub fn refresh_send_rate(&mut self, now: Instant) {
        if self.conn.config.datagram_send_queue_time.is_some() {
            self.conn.datagrams.send_rate.update(now, 0.0);
        }
    }

    /// Return the configured maximum unsent residence time.
    pub fn max_send_time(&self) -> Option<std::time::Duration> {
        self.conn.config.datagram_send_max_time
    }

    /// Reserve capacity for all fragments of one application packet.
    pub fn can_send_group(&mut self, bytes: usize) -> bool {
        if bytes <= self.send_buffer_space()
            || (self.conn.datagrams.outgoing_total == 0
                && bytes <= self.conn.config.datagram_send_buffer_size)
        {
            true
        } else {
            self.conn.datagrams.send_blocked = true;
            false
        }
    }

    /// Count a complete application packet discarded by the external sender.
    pub fn record_expired_packet(&mut self, datagrams: usize, bytes: usize) {
        self.conn.datagrams.expired_packets += 1;
        self.conn.datagrams.expired_datagrams += datagrams as u64;
        self.conn.datagrams.expired_bytes += bytes as u64;
    }
    fn send_buffer_limit(&self) -> usize {
        let hard_limit = self.conn.config.datagram_send_buffer_size;
        let Some(target) = self.conn.config.datagram_send_queue_time else {
            return hard_limit;
        };
        let rate = self
            .conn
            .path
            .congestion
            .metrics()
            .pacing_rate
            .map(|bits| bits as f64 / 8.0)
            .unwrap_or_else(|| {
                self.conn.path.congestion.window() as f64
                    / self.conn.path.rtt.get().as_secs_f64().max(0.001)
            });
        queue_byte_limit(
            rate.max(self.conn.datagrams.send_rate.max),
            target,
            self.conn.path.current_mtu(),
            hard_limit,
        )
    }

    /// Wait for actual FIFO drain when queue-time admission is enabled.
    pub fn send_queue_drained(&mut self) -> bool {
        if self.conn.config.datagram_send_queue_time.is_none()
            || self.conn.datagrams.outgoing_total == 0
        {
            true
        } else {
            self.conn.datagrams.send_blocked = true;
            false
        }
    }
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        self.send_with_deadline(data, drop, None, None, false)
    }

    /// Queue one fragment after its complete packet has passed capacity admission.
    pub fn send_with_deadline(
        &mut self,
        data: Bytes,
        drop: bool,
        deadline: Option<Instant>,
        group: Option<u64>,
        group_admitted: bool,
    ) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        if data.len() > max {
            return Err(SendDatagramError::TooLarge);
        }
        let limit = self.send_buffer_limit();
        if drop {
            while self.conn.datagrams.outgoing_total > limit {
                let prev = self
                    .conn
                    .datagrams
                    .outgoing
                    .pop_front()
                    .expect("datagrams.outgoing_total desynchronized");
                trace!(len = prev.frame.data.len(), "dropping outgoing datagram");
                self.conn.datagrams.outgoing_total -= prev.frame.data.len();
            }
        } else if self.conn.datagrams.outgoing_total + data.len()
            > self.conn.config.datagram_send_buffer_size
            || (self.conn.datagrams.outgoing_total + data.len() > limit && !group_admitted)
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.outgoing_total += data.len();
        self.conn.datagrams.outgoing.push_back(OutgoingDatagram {
            frame: Datagram { data },
            deadline,
            group,
        });
        Ok(())
    }

    /// Compute the maximum size of datagrams that may passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.path.current_mtu() as usize
            - self.conn.predict_1rtt_overhead(None)
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.send_buffer_limit()
            .saturating_sub(self.conn.datagrams.outgoing_total)
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    pub(super) send_rate: SendRate,
    /// Payload bytes not yet delivered to the application.
    pub(super) recv_buffered: usize,
    recv_retained: usize,
    incoming: VecDeque<ReceivedDatagram>,
    outgoing: VecDeque<OutgoingDatagram>,
    pub(super) outgoing_total: usize,
    pub(super) send_blocked: bool,
    pub(super) fast_send_blocked: bool,
    /// Payloads remain with the external sender until its next seal call.
    pub(super) fast_send_pending: bool,
    pub(super) expired_packets: u64,
    pub(super) expired_datagrams: u64,
    pub(super) expired_bytes: u64,
}

/// Retain recent rate peaks through congestion-controller drain and ProbeRTT.
#[derive(Default)]
pub(super) struct SendRate {
    buckets: [f64; 10],
    epoch: Option<Instant>,
    current: usize,
    max: f64,
}

impl SendRate {
    pub(super) fn update(&mut self, now: Instant, rate: f64) {
        let epoch = *self.epoch.get_or_insert(now);
        let steps = now.saturating_duration_since(epoch).as_millis() / 100;
        if steps != 0 {
            if steps >= self.buckets.len() as u128 {
                self.buckets.fill(0.0);
            } else {
                for _ in 0..steps {
                    self.current = (self.current + 1) % self.buckets.len();
                    self.buckets[self.current] = 0.0;
                }
            }
            self.epoch = Some(epoch + std::time::Duration::from_millis((steps * 100) as u64));
            self.max = self.buckets.iter().copied().fold(0.0, f64::max);
        }
        self.buckets[self.current] = self.buckets[self.current].max(rate);
        self.max = self.max.max(rate);
    }
}

struct OutgoingDatagram {
    frame: Datagram,
    deadline: Option<Instant>,
    group: Option<u64>,
}

struct ReceivedDatagram {
    data: Bytes,
    retained_bytes: usize,
}

impl DatagramState {
    pub(super) fn is_send_empty(&self) -> bool {
        self.outgoing.is_empty()
    }

    pub(super) fn can_send(&self, max_size: usize) -> bool {
        self.outgoing
            .front()
            .is_some_and(|datagram| datagram.frame.size(true) <= max_size)
    }

    pub(super) fn next_expiry(&self) -> Option<Instant> {
        self.outgoing
            .iter()
            .filter_map(|datagram| datagram.deadline)
            .min()
    }

    pub(super) fn expire(&mut self, now: Instant) -> bool {
        if self.next_expiry().is_none_or(|deadline| now < deadline) {
            return false;
        }
        let before = self.outgoing_total;
        let mut last_group = None;
        self.outgoing.retain(|datagram| {
            if datagram.deadline.is_none_or(|deadline| now < deadline) {
                return true;
            }
            if datagram.group.is_none() || datagram.group != last_group {
                self.expired_packets += 1;
            }
            last_group = datagram.group;
            self.expired_datagrams += 1;
            self.expired_bytes += datagram.frame.data.len() as u64;
            self.outgoing_total -= datagram.frame.data.len();
            false
        });
        self.outgoing_total != before
    }
    pub(super) fn received(
        &mut self,
        mut datagram: Datagram,
        mut retained_bytes: usize,
        window: &Option<usize>,
        drop_policy: DatagramReceiveDropPolicy,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        if datagram.data.len() > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        // Bound metadata for tiny and empty frames, including deque capacity growth.
        let max_datagrams = window.div_ceil(2 * std::mem::size_of::<ReceivedDatagram>());
        let was_empty = self.incoming.is_empty();
        if max_datagrams == 0 {
            return Ok(false);
        }
        if retained_bytes > window {
            // A small frame can retain a large padded packet. Copy only that oversized allocation.
            datagram.data = Bytes::copy_from_slice(&datagram.data);
            retained_bytes = datagram.data.len();
        }
        if (datagram.data.len() + self.recv_buffered > window
            || retained_bytes + self.recv_retained > window
            || self.incoming.len() >= max_datagrams)
            && drop_policy == DatagramReceiveDropPolicy::Newest
        {
            debug!("dropping newest datagram");
            return Ok(false);
        }
        while datagram.data.len() + self.recv_buffered > window
            || retained_bytes + self.recv_retained > window
            || self.incoming.len() >= max_datagrams
        {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.recv_buffered += datagram.data.len();
        self.recv_retained += retained_bytes;
        self.incoming.push_back(ReceivedDatagram {
            data: datagram.data,
            retained_bytes,
        });
        Ok(was_empty)
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let before = self.outgoing_total;
        let mut index = 0;
        while index < self.outgoing.len() {
            let group = self.outgoing[index].group;
            let count = if let Some(group) = group {
                self.outgoing
                    .range(index..)
                    .take_while(|datagram| datagram.group == Some(group))
                    .count()
            } else {
                1
            };
            if self
                .outgoing
                .range(index..index + count)
                .any(|datagram| datagram.frame.data.len() > max_payload)
            {
                for datagram in self.outgoing.drain(index..index + count) {
                    self.outgoing_total -= datagram.frame.data.len();
                }
            } else {
                index += count;
            }
        }
        self.outgoing_total != before
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write(&mut self, buf: &mut Vec<u8>, max_size: usize) -> bool {
        let datagram = match self.outgoing.pop_front() {
            Some(x) => x,
            None => return false,
        };

        if buf.len() + datagram.frame.size(true) > max_size {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            self.outgoing.push_front(datagram);
            return false;
        }

        if let Some(group) = datagram.group.filter(|_| datagram.deadline.is_some()) {
            // Once transmission starts, preserve all remaining fragments of this packet.
            for remaining in self
                .outgoing
                .iter_mut()
                .take_while(|remaining| remaining.group == Some(group))
            {
                remaining.deadline = None;
            }
        }
        trace!(len = datagram.frame.data.len(), "DATAGRAM");

        self.outgoing_total -= datagram.frame.data.len();
        datagram.frame.encode(true, buf);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        let datagram = self.incoming.pop_front()?;
        self.recv_buffered -= datagram.data.len();
        self.recv_retained -= datagram.retained_bytes;
        Some(datagram.data)
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}

#[cfg(test)]
mod mtu_limit_tests {
    use super::*;

    #[test]
    fn expiry_discards_whole_unstarted_groups_and_releases_capacity() {
        let now = Instant::now();
        let mut rate = SendRate::default();
        rate.update(now, 1_000_000_000.0);
        for millis in [100, 200, 750, 899] {
            rate.update(now + std::time::Duration::from_millis(millis), 1.0);
            assert_eq!(rate.max, 1_000_000_000.0);
        }
        rate.update(now + std::time::Duration::from_millis(1000), 2.0);
        assert_eq!(rate.max, 2.0);
        rate.update(now + std::time::Duration::from_millis(3000), 0.0);
        assert_eq!(rate.max, 0.0);
        let target = std::time::Duration::from_millis(4);
        assert_eq!(
            queue_byte_limit(450_000_000.0 / 8.0, target, 1500, 1_048_576),
            288_000
        );
        assert_eq!(
            queue_byte_limit(10_000_000_000.0 / 8.0, target, 1500, 1_048_576),
            1_048_576
        );
        assert_eq!(queue_byte_limit(1.0, target, 1500, 4096), 4096);
        let now = Instant::now();
        let mut state = DatagramState::default();
        for (group, deadline) in [
            (Some(1), now),
            (Some(1), now),
            (None, now),
            (Some(2), now + std::time::Duration::from_millis(1)),
            (Some(2), now + std::time::Duration::from_millis(1)),
        ] {
            state.outgoing.push_back(OutgoingDatagram {
                frame: Datagram {
                    data: Bytes::from_static(b"payload"),
                },
                group,
                deadline: Some(deadline),
            });
            state.outgoing_total += 7;
        }
        assert!(state.expire(now));
        assert_eq!(state.outgoing_total, 14);
        assert_eq!(
            (
                state.expired_packets,
                state.expired_datagrams,
                state.expired_bytes
            ),
            (2, 3, 21)
        );
        let mut buffer = Vec::new();
        assert!(state.write(&mut buffer, 1200));
        assert!(!state.expire(now + std::time::Duration::from_millis(10)));
        assert!(state.write(&mut buffer, 1200));
        assert_eq!(state.outgoing_total, 0);
        assert_eq!(state.expired_packets, 2);
        for length in [7, 1201] {
            state.outgoing.push_back(OutgoingDatagram {
                frame: Datagram {
                    data: Bytes::from(vec![0; length]),
                },
                group: Some(3),
                deadline: None,
            });
            state.outgoing_total += length;
        }
        assert!(state.drop_oversized(1200));
        assert!(state.is_send_empty());
        assert_eq!(state.outgoing_total, 0);
        for deadline in [now + std::time::Duration::from_millis(1), now] {
            state.outgoing.push_back(OutgoingDatagram {
                frame: Datagram {
                    data: Bytes::from_static(b"payload"),
                },
                group: None,
                deadline: Some(deadline),
            });
            state.outgoing_total += 7;
        }
        assert_eq!(state.next_expiry(), Some(now));
        assert!(state.expire(now));
        assert_eq!(state.outgoing_total, 7);
        assert_eq!(state.expired_packets, 3);
    }

    #[test]
    fn mtu_reduction_retains_datagrams_at_the_new_limit() {
        let window = Some(256);
        let mut receive = DatagramState::default();
        for _ in 0..100 {
            receive
                .received(
                    Datagram { data: Bytes::new() },
                    0,
                    &window,
                    DatagramReceiveDropPolicy::Newest,
                )
                .unwrap();
        }
        assert!(
            receive.incoming.len()
                <= 256_usize.div_ceil(2 * std::mem::size_of::<ReceivedDatagram>())
        );
        assert!(!receive.incoming.is_empty());
        while receive.recv().is_some() {}
        assert_eq!(receive.recv_buffered, 0);
        for _ in 0..100 {
            receive
                .received(
                    Datagram { data: Bytes::new() },
                    0,
                    &window,
                    DatagramReceiveDropPolicy::Oldest,
                )
                .unwrap();
        }
        assert!(
            receive.incoming.len()
                <= 256_usize.div_ceil(2 * std::mem::size_of::<ReceivedDatagram>())
        );
        assert_eq!(receive.recv().unwrap().len(), 0);
        while receive.recv().is_some() {}
        assert_eq!(receive.recv_buffered, 0);
        let padded = Bytes::from(vec![0x5a; 65536]);
        let slice = padded.slice(..1);
        let original = slice.as_ptr();
        receive
            .received(
                Datagram { data: slice },
                65536,
                &window,
                DatagramReceiveDropPolicy::Newest,
            )
            .unwrap();
        let compact = receive.recv().unwrap();
        assert_eq!(&compact[..], &[0x5a]);
        assert_ne!(compact.as_ptr(), original);
        assert_eq!(receive.recv_buffered, 0);
        assert_eq!(receive.recv_retained, 0);
        let data = Bytes::from(vec![0x3c; 128]);
        let original = data.as_ptr();
        receive
            .received(
                Datagram { data },
                144,
                &window,
                DatagramReceiveDropPolicy::Newest,
            )
            .unwrap();
        assert_eq!(receive.recv_retained, 144);
        assert_eq!(receive.recv().unwrap().as_ptr(), original);
        for policy in [
            DatagramReceiveDropPolicy::Newest,
            DatagramReceiveDropPolicy::Oldest,
        ] {
            receive
                .received(
                    Datagram {
                        data: Bytes::from(vec![1; 128]),
                    },
                    144,
                    &window,
                    policy,
                )
                .unwrap();
            receive
                .received(
                    Datagram {
                        data: Bytes::from(vec![2; 128]),
                    },
                    144,
                    &window,
                    policy,
                )
                .unwrap();
            assert_eq!(receive.incoming.len(), 1);
            assert_eq!(receive.recv_retained, 144);
            let expected = if policy == DatagramReceiveDropPolicy::Newest {
                1
            } else {
                2
            };
            assert_eq!(receive.recv().unwrap()[0], expected);
            assert_eq!(receive.recv_buffered, 0);
            assert_eq!(receive.recv_retained, 0);
        }
        let mut state = DatagramState::default();
        for length in [1199, 1200, 1201] {
            state.outgoing.push_back(OutgoingDatagram {
                frame: Datagram {
                    data: Bytes::from(vec![0; length]),
                },
                deadline: None,
                group: None,
            });
            state.outgoing_total += length;
        }

        state.drop_oversized(1200);

        let sizes: Vec<_> = state
            .outgoing
            .iter()
            .map(|packet| packet.frame.data.len())
            .collect();
        assert_eq!(sizes, [1199, 1200]);
        assert_eq!(state.outgoing_total, 2399);
    }
}
