use super::*;
use futures::{FutureExt, Sink, SinkExt};

#[tokio::test]
async fn sink_owner_drains_closed_lanes_and_exits() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    for controls in [0, MAX_CONSECUTIVE_CONTROL_SENDS] {
        let (control_tx, control_rx) = mpsc::channel(MAX_CONSECUTIVE_CONTROL_SENDS);
        let (data_tx, data_rx) = mpsc::channel(1);
        let budget = Arc::new(AdmissionBudget::with_process(controls + 1, 4096, None));
        for sender in std::iter::repeat_n(&control_tx, controls).chain(std::iter::once(&data_tx)) {
            sender
                .send(DirectSendWork {
                    batch: PacketBatch::singleton(ZCPacket::new_with_payload(&[0; 16])),
                    ownership: budget.try_acquire(1, 16).unwrap(),
                    deadline: None,
                })
                .await
                .unwrap();
        }
        drop(control_tx);
        let sent = Arc::new(AtomicUsize::new(0));
        let sink = futures::sink::unfold(sent.clone(), |sent, batch: PacketBatch| async move {
            sent.fetch_add(batch.len(), Ordering::Relaxed);
            Ok::<_, TunnelError>(sent)
        });
        let owner = run_direct_sink_owner(
            std::sync::Weak::new(),
            Box::pin(sink),
            control_rx,
            data_rx,
            Some(Duration::from_secs(1)),
        );
        tokio::pin!(owner);
        // The closed control lane must drain while the data lane remains open.
        assert!(futures::poll!(owner.as_mut()).is_pending());
        drop(data_tx);
        tokio::time::timeout(Duration::from_secs(1), owner)
            .await
            .unwrap();
        assert_eq!(sent.load(Ordering::Relaxed), controls + 1);
        let usage = budget.usage.lock();
        assert_eq!((usage.packets, usage.bytes, usage.runs), (0, 0, 0));
    }
}

#[tokio::test]
async fn queued_transit_observes_denial_before_framing() {
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::{Context, Poll},
    };
    struct GateSink {
        ready: Arc<AtomicBool>,
        sent: Arc<AtomicUsize>,
    }
    impl futures::Sink<PacketBatch> for GateSink {
        type Error = TunnelError;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.ready.load(Ordering::Acquire) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
        fn start_send(self: Pin<&mut Self>, batch: PacketBatch) -> Result<(), Self::Error> {
            self.sent.fetch_add(batch.len(), Ordering::Relaxed);
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }
    let context = crate::common::global_ctx::tests::get_mock_global_ctx();
    let drain = futures::sink::drain::<PacketBatch>().sink_map_err(|never| match never {});
    let state = DirectSinkState::new(Box::pin(drain), None, None);
    state.transit_context.set(Arc::downgrade(&context)).unwrap();
    let ready = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicUsize::new(0));
    let mut sink: BoxedPacketBatchSink = Box::pin(TransitSink {
        inner: Box::pin(GateSink {
            ready: ready.clone(),
            sent: sent.clone(),
        }),
        state: Arc::downgrade(&state),
    });
    let mut packet = ZCPacket::new_with_payload(&[0; 100]);
    packet.fill_peer_manager_hdr(2, 3, PacketType::Data as u8);
    packet.transit_data = true;
    let send = start_direct_batch(&mut sink, PacketBatch::singleton(packet), None);
    tokio::pin!(send);
    assert!(futures::poll!(send.as_mut()).is_pending());
    let mut flags = context.get_flags();
    flags.relay_config_mut().transit = crate::proto::common::TransitPolicy::Deny as i32;
    context.set_flags(flags);
    ready.store(true, Ordering::Release);
    assert!(send.await.is_ok());
    assert_eq!(sent.load(Ordering::Relaxed), 0);
    let mut local_sink = Box::pin(TransitSink {
        inner: Box::pin(GateSink {
            ready: ready.clone(),
            sent: sent.clone(),
        }),
        state: Arc::downgrade(&state),
    });
    let mut local = ZCPacket::new_with_payload(&[0; 100]);
    local.fill_peer_manager_hdr(1, 3, PacketType::Data as u8);
    local_sink
        .as_mut()
        .start_send(PacketBatch::singleton(local))
        .unwrap();
    assert_eq!(sent.load(Ordering::Relaxed), 1);

    let mut child = crate::common::global_ctx::tests::get_mock_global_ctx();
    Arc::get_mut(&mut child).unwrap().transit_parent = Arc::downgrade(&context);
    assert!(child.pace_receive(1).now_or_never().is_some());
    let mut flags = context.get_flags();
    flags
        .limits
        .get_or_insert_with(Default::default)
        .receive_bps = Some(1);
    context.set_flags(flags.clone());
    let burst = crate::common::control_config::MAX_TRANSIT_PACKET_BYTES as usize;
    assert!(context.pace_receive(burst + 1).now_or_never().is_none());
    assert!(child.pace_receive(1).now_or_never().is_none());
    flags.limits.as_mut().unwrap().receive_bps = None;
    context.set_flags(flags);
    assert!(context.pace_receive(1).now_or_never().is_some());
    assert!(child.pace_receive(1).now_or_never().is_some());
}

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
    let budget = Arc::new(AdmissionBudget::with_process_and_runs(
        DIRECT_DATA_PACKET_BUDGET,
        DIRECT_DATA_BYTE_BUDGET,
        DIRECT_INFLIGHT_RUN_CAPACITY,
        None,
    ));
    let held = budget.try_acquire(64, DIRECT_QUEUE_FLOOR).unwrap();
    assert!(budget.try_acquire(1, 1).is_none());
    drop(held);
    budget.usage.lock().byte_rate =
        (DIRECT_QUEUE_FLOOR * 2) as f64 / DIRECT_QUEUE_TARGET.as_secs_f64();
    let first = budget.try_acquire(64, DIRECT_QUEUE_FLOOR).unwrap();
    let second = budget.try_acquire(64, DIRECT_QUEUE_FLOOR).unwrap();
    assert!(budget.try_acquire(1, 1).is_none());
    drop((first, second));
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
