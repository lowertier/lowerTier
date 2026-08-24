use std::{
    cell::Cell,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, OnceLock},
    thread,
};

use crossbeam::channel::{Sender, TrySendError, bounded};
use rayon::prelude::*;

use crate::tunnel::batch::{PARALLEL_CRYPTO_MIN_BATCH_SIZE, SEND_PIPELINE_SLOT_COUNT};

pub(crate) const SEND_CRYPTO_SLOT_COUNT: usize = SEND_PIPELINE_SLOT_COUNT;

const DEVICE_CRYPTO_QUEUE_CAPACITY: usize = 1024;
const MAX_DEVICE_CRYPTO_WORKERS: usize = 8;

thread_local! {
    static IN_DEVICE_CRYPTO_WORKER: Cell<bool> = const { Cell::new(false) };
}

#[inline]
fn in_device_crypto_worker() -> bool {
    IN_DEVICE_CRYPTO_WORKER.get()
}

/// An owner of stable, indexed crypto slots.
///
/// The device queue carries only this owner handle and a slot index. Packet
/// storage remains in the owner's bounded slot array for the whole job.
pub(crate) trait IndexedCryptoJob: Send + Sync + 'static {
    fn process_crypto_slot(&self, slot_index: usize);
    fn mark_crypto_slot_dead(&self, slot_index: usize);
}

struct DeviceCryptoWork {
    owner: Arc<dyn IndexedCryptoJob>,
    slot_index: u16,
}

struct DeviceCryptoQueue {
    sender: Sender<DeviceCryptoWork>,
}

impl DeviceCryptoQueue {
    fn new() -> Self {
        let (sender, receiver) = bounded::<DeviceCryptoWork>(DEVICE_CRYPTO_QUEUE_CAPACITY);
        let worker_count = thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .clamp(1, MAX_DEVICE_CRYPTO_WORKERS);

        for worker_index in 0..worker_count {
            let receiver = receiver.clone();
            thread::Builder::new()
                .name(format!("lowertier-crypto-{worker_index}"))
                .spawn(move || {
                    while let Ok(work) = receiver.recv() {
                        let slot_index = usize::from(work.slot_index);
                        let result = IN_DEVICE_CRYPTO_WORKER.with(|in_worker| {
                            let previous = in_worker.replace(true);
                            debug_assert!(!previous);
                            let result = catch_unwind(AssertUnwindSafe(|| {
                                work.owner.process_crypto_slot(slot_index);
                            }));
                            in_worker.set(previous);
                            result
                        });
                        if result.is_err() {
                            work.owner.mark_crypto_slot_dead(slot_index);
                            tracing::error!(
                                slot_index,
                                "indexed crypto worker panicked; slot marked DEAD"
                            );
                        }
                    }
                })
                .expect("LowTier must be able to spawn its persistent crypto workers");
        }

        Self { sender }
    }
}

fn device_crypto_queue() -> &'static DeviceCryptoQueue {
    static DEVICE_CRYPTO_QUEUE: OnceLock<DeviceCryptoQueue> = OnceLock::new();
    DEVICE_CRYPTO_QUEUE.get_or_init(DeviceCryptoQueue::new)
}

/// Resolve the emergency/debug opt-out once when a protected tunnel is built.
/// Packet processing never reads the environment or branches on this setting.
pub(crate) fn send_crypto_pipeline_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("LOWTIER_DEBUG_DISABLE_ASYNC_CRYPTO_PIPELINE").is_none())
}

/// Queue one stable slot index for a persistent device worker.
///
/// A full or disconnected device queue returns `false`; the caller then owns
/// the slot and can execute it synchronously without allocating another job.
pub(crate) fn try_submit_indexed_crypto_job(
    owner: Arc<dyn IndexedCryptoJob>,
    slot_index: usize,
) -> bool {
    let slot_index = u16::try_from(slot_index).expect("crypto slot index must fit in u16");
    let work = DeviceCryptoWork { owner, slot_index };
    match device_crypto_queue().sender.try_send(work) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
    }
}

/// Mutate one fixed input window without allocating task or result objects.
/// Synchronous callers can share a large run through Rayon. A persistent device
/// worker executes its assigned slot locally because slot-level parallelism is
/// already active and a nested Rayon barrier would oversubscribe the machine.
pub(crate) fn ordered_in_place_transform<T, E, F>(items: &mut [T], transform: F) -> Result<(), E>
where
    T: Send,
    E: Send,
    F: Fn(usize, &mut T) -> Result<(), E> + Send + Sync,
{
    if items.len() < PARALLEL_CRYPTO_MIN_BATCH_SIZE || in_device_crypto_worker() {
        return items
            .iter_mut()
            .enumerate()
            .try_for_each(|(index, item)| transform(index, item));
    }

    items
        .par_iter_mut()
        .enumerate()
        .try_for_each(|(index, item)| transform(index, item))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::Duration,
    };

    use super::{IndexedCryptoJob, ordered_in_place_transform, try_submit_indexed_crypto_job};

    #[test]
    fn fixed_slots_preserve_input_order_after_reversed_completion() {
        let mut values = (0_u8..64).collect::<Vec<_>>();

        ordered_in_place_transform(&mut values, |index, value| {
            std::thread::sleep(Duration::from_micros((64 - index) as u64));
            *value += 10;
            Ok::<(), ()>(())
        })
        .unwrap();

        assert_eq!(values, (10_u8..74).collect::<Vec<_>>());
    }

    #[test]
    fn singleton_transform_executes_on_the_calling_thread() {
        let caller = std::thread::current().id();
        let mut values = [7_u8];

        ordered_in_place_transform(&mut values, move |_, value| {
            assert_eq!(std::thread::current().id(), caller);
            *value += 1;
            Ok::<(), ()>(())
        })
        .unwrap();

        assert_eq!(values, [8]);
    }

    #[test]
    fn bulk_batch_uses_crypto_workers_without_contention() {
        let caller = std::thread::current().id();
        let observed = Arc::new(Mutex::new(HashSet::new()));
        let worker_observed = observed.clone();
        let mut values = (0_u8..64).collect::<Vec<_>>();

        ordered_in_place_transform(&mut values, move |_, value| {
            worker_observed
                .lock()
                .unwrap()
                .insert(std::thread::current().id());
            std::thread::sleep(Duration::from_millis(1));
            *value += 1;
            Ok::<(), ()>(())
        })
        .unwrap();

        let observed = observed.lock().unwrap();
        assert!(observed.iter().all(|thread| *thread != caller));
        if rayon::current_num_threads() > 1 {
            assert!(observed.len() > 1);
        }
        assert_eq!(values, (1_u8..=64).collect::<Vec<_>>());
    }

    #[test]
    fn fixed_completion_window_reuses_the_input_allocation() {
        let mut input = Vec::with_capacity(64);
        input.extend(0_u8..64);
        let original_pointer = input.as_ptr();

        ordered_in_place_transform(&mut input, |_, value| {
            *value += 1;
            Ok::<(), ()>(())
        })
        .unwrap();

        assert_eq!(input.as_ptr(), original_pointer);
        assert_eq!(input.capacity(), 64);
    }

    struct TestIndexedJob {
        completed: mpsc::Sender<usize>,
    }

    struct WorkerTransformJob {
        completed: mpsc::Sender<bool>,
    }

    impl IndexedCryptoJob for WorkerTransformJob {
        fn process_crypto_slot(&self, _slot_index: usize) {
            let worker_id = std::thread::current().id();
            let stayed_on_worker = AtomicBool::new(true);
            let mut values = (0_u8..64).collect::<Vec<_>>();

            ordered_in_place_transform(&mut values, |_, value| {
                if std::thread::current().id() != worker_id {
                    stayed_on_worker.store(false, Ordering::Relaxed);
                }
                *value += 1;
                Ok::<(), ()>(())
            })
            .unwrap();

            self.completed
                .send(stayed_on_worker.load(Ordering::Relaxed))
                .unwrap();
        }

        fn mark_crypto_slot_dead(&self, slot_index: usize) {
            panic!("unexpected DEAD slot {slot_index}");
        }
    }

    impl IndexedCryptoJob for TestIndexedJob {
        fn process_crypto_slot(&self, slot_index: usize) {
            self.completed.send(slot_index).unwrap();
        }

        fn mark_crypto_slot_dead(&self, slot_index: usize) {
            panic!("unexpected DEAD slot {slot_index}");
        }
    }

    #[test]
    fn persistent_worker_avoids_nested_rayon() {
        let (completed, receiver) = mpsc::channel();
        let owner: Arc<dyn IndexedCryptoJob> = Arc::new(WorkerTransformJob { completed });

        assert!(try_submit_indexed_crypto_job(owner, 0));
        assert!(receiver.recv_timeout(Duration::from_secs(2)).unwrap());
    }

    #[test]
    fn bounded_device_queue_dispatches_stable_slot_indices() {
        let (completed, receiver) = mpsc::channel();
        let owner: Arc<dyn IndexedCryptoJob> = Arc::new(TestIndexedJob { completed });

        assert!(try_submit_indexed_crypto_job(owner, 5));
        assert_eq!(receiver.recv_timeout(Duration::from_secs(2)).unwrap(), 5);
    }
}
