use super::*;
use futures::{FutureExt, SinkExt};

#[tokio::test]
async fn byte_budget_rejection_parks_until_real_release() {
    let budget = Arc::new(AdmissionBudget::with_process(4, 8, None));
    let held = budget.try_acquire(1, 8).unwrap();
    let notified = budget.wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    for _ in 0..16 {
        assert!(budget.try_acquire(1, 1).is_none());
        assert!(
            notified.as_mut().now_or_never().is_none(),
            "rejection woke its own retry"
        );
        let usage = budget.usage.lock();
        assert_eq!((usage.packets, usage.bytes), (1, 8));
    }
    drop(held);
    assert!(notified.as_mut().now_or_never().is_some());
    assert!(budget.try_acquire(1, 1).is_some());
}

#[tokio::test]
async fn packet_and_run_rejections_leave_no_partial_reservation() {
    for (packets, runs) in [(1, 4), (4, 1)] {
        let budget = Arc::new(AdmissionBudget::with_process_and_runs(
            packets, 16, runs, None,
        ));
        let held = budget.try_acquire(1, 4).unwrap();
        let notified = budget.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        assert!(budget.try_acquire(1, 4).is_none());
        assert!(notified.as_mut().now_or_never().is_none());
        {
            let usage = budget.usage.lock();
            assert_eq!((usage.packets, usage.bytes, usage.runs), (1, 4, 1));
        }
        drop(held);
        assert!(notified.as_mut().now_or_never().is_some());
        let usage = budget.usage.lock();
        assert_eq!((usage.packets, usage.bytes, usage.runs), (0, 0, 0));
    }
}

#[tokio::test]
async fn process_memory_release_wakes_an_independent_lane() {
    let process = Arc::new(ProcessMemoryGovernor::with_limit(8));
    let other_lane = process.try_reserve_owned(8).unwrap();
    let sink = futures::sink::drain::<PacketBatch>().sink_map_err(|never| match never {});
    let state = DirectSinkState::new(Box::pin(sink), None, Some(process.clone()));
    let wait = acquire_batch_ownership(
        &state,
        DirectBatchPlan {
            control: false,
            packet_count: 1,
            byte_count: 8,
        },
    );
    tokio::pin!(wait);
    assert!(futures::poll!(wait.as_mut()).is_pending());
    drop(other_lane);
    let permit = tokio::time::timeout(Duration::from_secs(1), wait)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(process.retained(), 8);
    drop(permit);
    assert_eq!(process.retained(), 0);
}

#[tokio::test]
async fn failed_local_admission_never_temporarily_reserves_shared_memory() {
    let process = Arc::new(ProcessMemoryGovernor::with_limit(32));
    let budget = Arc::new(AdmissionBudget::with_process(1, 16, Some(process.clone())));
    let held = budget.try_acquire(1, 8).unwrap();
    let notified = process.release_notified();
    tokio::pin!(notified);
    for _ in 0..16 {
        assert!(budget.try_acquire(1, 8).is_none());
        assert_eq!(process.retained(), 8);
        assert!(notified.as_mut().now_or_never().is_none());
    }
    drop(held);
    assert_eq!(process.retained(), 0);
    assert!(notified.as_mut().now_or_never().is_some());
}

#[tokio::test]
async fn shared_release_before_first_poll_is_observed() {
    let process = Arc::new(ProcessMemoryGovernor::with_limit(8));
    let held = process.try_reserve_owned(8).unwrap();
    let notified = process.release_notified();
    drop(held);
    assert!(notified.now_or_never().is_some());
}
