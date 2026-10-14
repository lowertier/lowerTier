use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::Connection;
use crate::{
    DatagramReceiveDropPolicy, TransportError,
    frame::{Datagram, FrameStruct},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
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
        ((rate * target.as_secs_f64()) as usize)
            .max(3 * 64 * usize::from(self.conn.path.current_mtu()))
            .min(hard_limit)
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
                trace!(len = prev.data.len(), "dropping outgoing datagram");
                self.conn.datagrams.outgoing_total -= prev.data.len();
            }
        } else if self.conn.datagrams.outgoing_total + data.len() > limit {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.outgoing_total += data.len();
        self.conn.datagrams.outgoing.push_back(Datagram { data });
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
    /// Payload bytes not yet delivered to the application.
    pub(super) recv_buffered: usize,
    recv_retained: usize,
    incoming: VecDeque<ReceivedDatagram>,
    pub(super) outgoing: VecDeque<Datagram>,
    pub(super) outgoing_total: usize,
    pub(super) send_blocked: bool,
    pub(super) fast_send_blocked: bool,
    /// Payloads remain with the external sender until its next seal call.
    pub(super) fast_send_pending: bool,
}

struct ReceivedDatagram {
    data: Bytes,
    retained_bytes: usize,
}

impl DatagramState {
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
    pub(super) fn drop_oversized(&mut self, max_payload: usize) {
        self.outgoing.retain(|datagram| {
            let result = datagram.data.len() <= max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.data.len(),
                    max_payload
                );
                self.outgoing_total -= datagram.data.len();
            }
            result
        });
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

        if buf.len() + datagram.size(true) > max_size {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            self.outgoing.push_front(datagram);
            return false;
        }

        trace!(len = datagram.data.len(), "DATAGRAM");

        self.outgoing_total -= datagram.data.len();
        datagram.encode(true, buf);
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
            state.outgoing.push_back(Datagram {
                data: Bytes::from(vec![0; length]),
            });
            state.outgoing_total += length;
        }

        state.drop_oversized(1200);

        let sizes: Vec<_> = state
            .outgoing
            .iter()
            .map(|packet| packet.data.len())
            .collect();
        assert_eq!(sizes, [1199, 1200]);
        assert_eq!(state.outgoing_total, 2399);
    }
}
