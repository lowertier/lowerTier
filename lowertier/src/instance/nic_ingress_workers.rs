//! Persistent delivery lifetimes using the fair-ingress owner's existing credits.
//!
//! Each worker owns one fixed job slot. No mailbox semaphore or additional
//! packet budget is needed: a slot cannot be reused until its completion is
//! consumed. Completion order is FIFO across workers and flow order is enforced
//! by the unchanged admission queue.
use std::{future::Future, sync::Arc};

use crossbeam::queue::ArrayQueue;
use parking_lot::Mutex;
use tokio::{sync::Notify, task::JoinSet};

use super::nic_ingress::ACTIVE_FLOW_LIMIT;
use crate::tunnel::batch::PacketBatch;

pub(super) type IngressJob = (u64, PacketBatch);
pub(super) type IngressCompletion = (usize, u64);

struct JobSlot {
    job: Mutex<Option<IngressJob>>,
    ready: Notify,
}

pub(super) struct JobReceiver(Arc<JobSlot>);

impl JobReceiver {
    /// One consumer per slot. A stored Notify permit covers a send between the
    /// empty check and suspension; taking a job has no intervening await.
    pub(super) async fn recv(&mut self) -> Option<IngressJob> {
        loop {
            if let Some(job) = self.0.job.lock().take() {
                return Some(job);
            }
            self.0.ready.notified().await;
        }
    }
}

struct Completions {
    queue: ArrayQueue<IngressCompletion>,
    ready: Notify,
}

#[derive(Clone)]
pub(super) struct CompletionSender(Arc<Completions>);

impl CompletionSender {
    pub(super) async fn send(&self, value: IngressCompletion) -> Result<(), String> {
        self.0
            .queue
            .push(value)
            .map_err(|_| "NIC completion ring unexpectedly full".to_owned())?;
        self.0.ready.notify_one();
        Ok(())
    }
}

pub(super) struct NicIngressWorkers {
    workers: JoinSet<()>,
    slots: Box<[Arc<JobSlot>]>,
    completed: Arc<Completions>,
    free: Vec<usize>,
    busy: [Option<u64>; ACTIVE_FLOW_LIMIT],
}

impl NicIngressWorkers {
    pub(super) fn new<F, Fut>(make_worker: F) -> Self
    where
        F: Fn(usize, JobReceiver, CompletionSender) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let completed = Arc::new(Completions {
            queue: ArrayQueue::new(ACTIVE_FLOW_LIMIT),
            ready: Notify::new(),
        });
        let mut workers = JoinSet::new();
        let mut slots = Vec::with_capacity(ACTIVE_FLOW_LIMIT);
        for index in 0..ACTIVE_FLOW_LIMIT {
            let slot = Arc::new(JobSlot {
                job: Mutex::new(None),
                ready: Notify::new(),
            });
            workers.spawn(make_worker(
                index,
                JobReceiver(slot.clone()),
                CompletionSender(completed.clone()),
            ));
            slots.push(slot);
        }
        Self {
            workers,
            slots: slots.into_boxed_slice(),
            completed,
            free: (0..ACTIVE_FLOW_LIMIT).rev().collect(),
            busy: [None; ACTIVE_FLOW_LIMIT],
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.free.len() == ACTIVE_FLOW_LIMIT
    }

    pub(super) fn submit(&mut self, hash: u64, batch: PacketBatch) -> Result<(), String> {
        let index = self.free.pop().ok_or("NIC delivery slots exhausted")?;
        debug_assert!(self.busy[index].is_none());
        let slot = &self.slots[index];
        {
            let mut job = slot.job.lock();
            if job.is_some() {
                self.free.push(index);
                return Err("NIC delivery slot reused before consumption".to_owned());
            }
            self.busy[index] = Some(hash);
            *job = Some((hash, batch));
        }
        slot.ready.notify_one();
        Ok(())
    }

    /// Only the admission owner consumes completions. Always drain the ring
    /// before awaiting its coalescing notification. Unexpected task exit is
    /// terminal and is checked before accepting any completion.
    pub(super) async fn next(&mut self) -> Result<u64, String> {
        loop {
            if let Some(exited) = self.workers.try_join_next() {
                return Err(format!("persistent NIC delivery worker exited: {exited:?}"));
            }
            if let Some((index, hash)) = self.completed.queue.pop() {
                let slot = self
                    .busy
                    .get_mut(index)
                    .ok_or("invalid NIC completion slot")?;
                if *slot != Some(hash) {
                    return Err("NIC completion did not match its active flow".to_owned());
                }
                *slot = None;
                self.free.push(index);
                return Ok(hash);
            }
            tokio::select! {
                biased;
                exited = self.workers.join_next() => {
                    return Err(format!("persistent NIC delivery worker exited: {exited:?}"));
                }
                _ = self.completed.ready.notified() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use tokio::{sync::Notify, time::timeout};

    use super::*;
    use crate::tunnel::packet_def::ZCPacket;

    fn batch(value: u8) -> PacketBatch {
        PacketBatch::singleton(ZCPacket::new_with_payload(&[value; 1200]))
    }

    fn echo_workers(started: Arc<AtomicUsize>) -> NicIngressWorkers {
        NicIngressWorkers::new(move |index, mut jobs, completed| {
            let started = started.clone();
            async move {
                started.fetch_add(1, Ordering::Relaxed);
                while let Some((hash, packet)) = jobs.recv().await {
                    assert_eq!(packet[0].payload()[0], hash as u8);
                    if completed.send((index, hash)).await.is_err() {
                        return;
                    }
                }
            }
        })
    }

    #[tokio::test]
    async fn reuses_fixed_workers_for_many_batches() {
        let started = Arc::new(AtomicUsize::new(0));
        let mut workers = echo_workers(started.clone());
        for value in 0..200_u64 {
            workers.submit(value, batch(value as u8)).unwrap();
            assert_eq!(
                timeout(Duration::from_secs(2), workers.next())
                    .await
                    .unwrap()
                    .unwrap(),
                value
            );
            assert!(workers.is_empty());
        }
        assert_eq!(started.load(Ordering::Relaxed), ACTIVE_FLOW_LIMIT);
    }

    #[tokio::test]
    async fn active_slots_bound_all_mailboxes_and_completions() {
        let started = Arc::new(AtomicUsize::new(0));
        let mut workers = echo_workers(started);
        for value in 0..ACTIVE_FLOW_LIMIT as u64 {
            workers.submit(value, batch(value as u8)).unwrap();
        }
        assert!(workers.submit(1000, batch(0)).is_err());
        assert!(!workers.is_empty());
        let mut seen = vec![false; ACTIVE_FLOW_LIMIT];
        for _ in 0..ACTIVE_FLOW_LIMIT {
            let hash = timeout(Duration::from_secs(2), workers.next())
                .await
                .unwrap()
                .unwrap();
            assert!(!seen[hash as usize]);
            seen[hash as usize] = true;
        }
        assert!(seen.into_iter().all(|value| value));
        assert!(workers.is_empty());
    }

    #[tokio::test]
    async fn blocked_bulk_flow_does_not_block_independent_completion() {
        let release = Arc::new(Notify::new());
        let mut workers = NicIngressWorkers::new({
            let release = release.clone();
            move |index, mut jobs, completed| {
                let release = release.clone();
                async move {
                    while let Some((hash, _)) = jobs.recv().await {
                        if hash == 1 {
                            release.notified().await;
                        }
                        if completed.send((index, hash)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
        workers.submit(1, batch(1)).unwrap();
        workers.submit(2, batch(2)).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), workers.next())
                .await
                .unwrap()
                .unwrap(),
            2
        );
        release.notify_one();
        assert_eq!(
            timeout(Duration::from_secs(2), workers.next())
                .await
                .unwrap()
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn queue_and_worker_handoff_preserve_same_flow_fifo() {
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut workers = NicIngressWorkers::new({
            let observed = observed.clone();
            move |index, mut jobs, completed| {
                let observed = observed.clone();
                async move {
                    while let Some((hash, batch)) = jobs.recv().await {
                        observed
                            .lock()
                            .unwrap()
                            .extend(batch.iter().map(|packet| packet.payload()[0]));
                        if completed.send((index, hash)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let mut queue = super::super::nic_ingress::NicIngressQueue::default();
        for value in 0..192_u8 {
            queue.push(7, ZCPacket::new_with_payload(&[value; 1200]));
        }
        while let Some((hash, batch)) = queue.pop() {
            workers.submit(hash, batch).unwrap();
            assert!(queue.pop().is_none());
            let completed = timeout(Duration::from_secs(2), workers.next())
                .await
                .unwrap()
                .unwrap();
            queue.complete(completed);
        }
        assert_eq!(*observed.lock().unwrap(), (0..192_u8).collect::<Vec<_>>());
        assert!(workers.is_empty());
    }

    #[tokio::test]
    async fn worker_panic_is_terminal_instead_of_stranding_a_flow() {
        let mut workers = NicIngressWorkers::new(|_index, mut jobs, _completed| async move {
            if jobs.recv().await.is_some() {
                panic!("intentional worker failure");
            }
        });
        workers.submit(9, batch(9)).unwrap();
        assert!(
            timeout(Duration::from_secs(2), workers.next())
                .await
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_completion_ring_conserves_every_active_slot() {
        let mut workers = echo_workers(Arc::new(AtomicUsize::new(0)));
        timeout(Duration::from_secs(20), async {
            for round in 0..1000_u64 {
                let first = round * ACTIVE_FLOW_LIMIT as u64;
                for index in 0..ACTIVE_FLOW_LIMIT as u64 {
                    let hash = first + index;
                    workers.submit(hash, batch(hash as u8)).unwrap();
                }
                let mut seen = 0_u64;
                for _ in 0..ACTIVE_FLOW_LIMIT {
                    let hash = workers.next().await.unwrap();
                    let index = hash
                        .checked_sub(first)
                        .expect("completion belongs to this round");
                    assert!(index < ACTIVE_FLOW_LIMIT as u64);
                    let bit = 1_u64 << index;
                    assert_eq!(seen & bit, 0, "each slot completes exactly once");
                    seen |= bit;
                }
                assert_eq!(seen.count_ones() as usize, ACTIVE_FLOW_LIMIT);
                assert!(workers.is_empty());
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_completion_wait_does_not_lose_notification() {
        let mut workers = echo_workers(Arc::new(AtomicUsize::new(0)));
        let mut pending = Box::pin(workers.next());
        assert!(futures::poll!(pending.as_mut()).is_pending());
        drop(pending);
        workers.submit(3, batch(3)).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), workers.next())
                .await
                .unwrap()
                .unwrap(),
            3
        );
        assert!(workers.is_empty());
    }

    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn dropping_owner_cancels_all_persistent_workers() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let workers = NicIngressWorkers::new({
            let dropped = dropped.clone();
            move |_index, _jobs, _completed| {
                let guard = DropCounter(dropped.clone());
                async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                }
            }
        });
        tokio::task::yield_now().await;
        drop(workers);
        timeout(Duration::from_secs(2), async {
            while dropped.load(Ordering::Acquire) != ACTIVE_FLOW_LIMIT {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
