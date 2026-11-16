use std::{
    ffi::{c_char, c_int, c_void},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use lowertier::{
    instance::virtual_nic::NicCtx,
    tunnel::{
        SplitTunnel,
        batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
        packet_def::ZCPacket,
        ring::create_ring_tunnel_pair,
    },
};
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;

use crate::{
    error::set_error_msg,
    state::{ASYNC_RUNTIME, INSTANCE_MANAGER, find_instance_id_by_name},
    strings::c_str_to_string,
};

#[repr(C)]
pub struct PacketSlice {
    pub data: *const u8,
    pub length: usize,
}

pub type PacketReceiver = unsafe extern "C" fn(*const PacketSlice, usize, *mut c_void) -> c_int;

struct PacketFlow {
    instance: Option<uuid::Uuid>,
    sender: Mutex<std::pin::Pin<Box<dyn lowertier::tunnel::PacketBatchSink>>>,
    cancel: CancellationToken,
    receiver: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static FLOWS: once_cell::sync::Lazy<DashMap<u64, Arc<PacketFlow>>> =
    once_cell::sync::Lazy::new(DashMap::new);

fn register(
    instance: Option<uuid::Uuid>,
    nic: Option<NicCtx>,
    endpoint: SplitTunnel,
    receiver: PacketReceiver,
    context: usize,
) -> u64 {
    let (mut incoming, outgoing) = endpoint;
    let cancel = CancellationToken::new();
    let stopped = cancel.clone();
    let task = ASYNC_RUNTIME.spawn(async move {
        let _nic = nic;
        loop {
            let batch = tokio::select! {
                biased;
                _ = stopped.cancelled() => break,
                batch = incoming.next() => match batch {
                    Some(Ok(batch)) => batch,
                    _ => { stopped.cancel(); break }
                },
            };
            let slices = batch
                .iter()
                .map(|packet| PacketSlice {
                    data: packet.payload().as_ptr(),
                    length: packet.payload().len(),
                })
                .collect::<Vec<_>>();
            // The native callback copies data before returning. The batch owns it until then.
            if unsafe { receiver(slices.as_ptr(), slices.len(), context as *mut c_void) } != 0 {
                stopped.cancel();
                break;
            }
        }
    });
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    FLOWS.insert(
        handle,
        Arc::new(PacketFlow {
            instance,
            sender: Mutex::new(outgoing),
            cancel,
            receiver: Mutex::new(Some(task)),
        }),
    );
    handle
}

pub(crate) unsafe fn open(
    name: *const c_char,
    receiver: Option<PacketReceiver>,
    context: *mut c_void,
    handle: *mut u64,
) -> c_int {
    if handle.is_null() {
        set_error_msg("The packet handle output is null.");
        return -1;
    }
    unsafe { *handle = 0 };
    let result = (|| -> Result<Option<u64>, String> {
        let name = unsafe { c_str_to_string(name, "name") }?;
        let receiver = receiver.ok_or("The packet receiver is null.")?;
        let _mutation = crate::state::INSTANCE_MUTATION_LOCK
            .lock()
            .map_err(|_| "The instance mutation lock is unavailable.")?;
        let id = find_instance_id_by_name(&name)
            .ok_or("The packet-tunnel instance is not registered.")?;
        let Some(service) = INSTANCE_MANAGER.get_instance_service(&id) else {
            return Ok(None);
        };
        let _runtime = ASYNC_RUNTIME.enter();
        let context_state = service.context().map_err(|error| error.to_string())?;
        let peers = service.peers().map_err(|error| error.to_string())?;
        let (core, native) = create_ring_tunnel_pair();
        let mut nic = NicCtx::new(context_state, &peers, Arc::new(Notify::new()));
        nic.run_for_packet_flow(core)
            .map_err(|error| error.to_string())?;
        Ok(Some(register(
            Some(id),
            Some(nic),
            native.split(),
            receiver,
            context as usize,
        )))
    })();
    match result {
        Ok(Some(opened)) => {
            unsafe { *handle = opened };
            0
        }
        Ok(None) => 1,
        Err(error) => {
            set_error_msg(&error);
            -1
        }
    }
}

pub(crate) unsafe fn send(handle: u64, packets: *const PacketSlice, count: usize) -> c_int {
    let Some(flow) = FLOWS.get(&handle).map(|flow| flow.clone()) else {
        set_error_msg("The packet-tunnel handle is closed.");
        return -1;
    };
    if count == 0 {
        return 0;
    }
    if packets.is_null() || count > MAX_PACKET_BATCH_SIZE {
        set_error_msg("The packet batch is null or exceeds the core batch capacity.");
        return -1;
    }
    let mut batch = PacketBatch::with_capacity(count);
    for packet in unsafe { std::slice::from_raw_parts(packets, count) } {
        if packet.data.is_null() || packet.length < 20 || packet.length > 1280 {
            set_error_msg("The IP packet length is invalid.");
            return -1;
        }
        let data = unsafe { std::slice::from_raw_parts(packet.data, packet.length) };
        if !matches!(data[0] >> 4, 4 | 6) || (data[0] >> 4 == 6 && data.len() < 40) {
            set_error_msg("The IP packet version is invalid.");
            return -1;
        }
        batch
            .try_push(ZCPacket::new_with_payload(data))
            .expect("validated packet batch capacity");
    }
    let result = ASYNC_RUNTIME.block_on(async {
        tokio::select! {
            biased;
            _ = flow.cancel.cancelled() => Err("The packet tunnel is stopped.".into()),
            result = async { flow.sender.lock().await.send(batch).await } => result.map_err(|error| error.to_string()),
        }
    });
    match result {
        Ok(()) => 0,
        Err(error) => {
            set_error_msg(&error);
            -1
        }
    }
}

pub(crate) fn close(handle: u64) -> c_int {
    let Some(flow) = FLOWS.get(&handle).map(|flow| flow.clone()) else {
        return -1;
    };
    flow.cancel.cancel();
    ASYNC_RUNTIME.block_on(async {
        // All close callers share this barrier before the handle can disappear.
        let mut receiver = flow.receiver.lock().await;
        if let Some(task) = receiver.take() {
            let _ = task.await;
        }
    });
    FLOWS.remove(&handle);
    0
}

pub(crate) fn remove_by_instances(ids: &[uuid::Uuid]) {
    let handles = FLOWS
        .iter()
        .filter(|flow| flow.instance.is_some_and(|id| ids.contains(&id)))
        .map(|flow| *flow.key())
        .collect::<Vec<_>>();
    for handle in handles {
        close(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicUsize, mpsc};
    use std::time::Duration;

    struct Observer {
        packets: std::sync::Mutex<Vec<Vec<u8>>>,
        calls: AtomicUsize,
        ready: mpsc::Sender<()>,
    }

    unsafe extern "C" fn receive(
        packets: *const PacketSlice,
        count: usize,
        context: *mut c_void,
    ) -> c_int {
        let observer = unsafe { &*(context as *const Observer) };
        let mut saved = observer.packets.lock().unwrap();
        for packet in unsafe { std::slice::from_raw_parts(packets, count) } {
            saved.push(unsafe { std::slice::from_raw_parts(packet.data, packet.length) }.to_vec());
        }
        observer.calls.fetch_add(1, Ordering::SeqCst);
        observer.ready.send(()).unwrap();
        0
    }

    #[test]
    fn packet_flow_preserves_batches_and_close_cancels_full_queue() {
        let (ready, received) = mpsc::channel();
        let observer = Box::new(Observer {
            packets: std::sync::Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            ready,
        });
        let (peer, native) = create_ring_tunnel_pair();
        let handle = register(
            None,
            None,
            native.split(),
            receive,
            (&*observer as *const Observer) as usize,
        );
        let (mut stream, mut sink) = peer.split();
        let data = vec![0x45; 1280];
        let slices = [PacketSlice {
            data: data.as_ptr(),
            length: data.len(),
        }];
        assert_eq!(unsafe { send(handle, slices.as_ptr(), 1) }, 0);
        let batch = ASYNC_RUNTIME.block_on(stream.next()).unwrap().unwrap();
        assert_eq!(batch.iter().next().unwrap().payload(), data.as_slice());
        ASYNC_RUNTIME.block_on(sink.send(batch)).unwrap();
        received.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(observer.packets.lock().unwrap().as_slice(), [data.clone()]);
        let (done_tx, done_rx) = mpsc::channel();
        let sender = std::thread::spawn(move || {
            let data = vec![0x60; 1280];
            let packets = (0..MAX_PACKET_BATCH_SIZE)
                .map(|_| PacketSlice {
                    data: data.as_ptr(),
                    length: data.len(),
                })
                .collect::<Vec<_>>();
            loop {
                if unsafe { send(handle, packets.as_ptr(), packets.len()) } < 0 {
                    break;
                }
            }
            done_tx.send(()).unwrap();
        });
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        assert_eq!(close(handle), 0);
        done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        sender.join().unwrap();
        assert_eq!(observer.calls.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { send(handle, slices.as_ptr(), 1) }, -1);
    }

    #[test]
    fn packet_flow_attachment_has_one_owner_and_can_reopen() {
        use std::ffi::CString;

        unsafe extern "C" fn discard(_: *const PacketSlice, _: usize, _: *mut c_void) -> c_int {
            0
        }
        let name = format!("packet-flow-{}", uuid::Uuid::new_v4());
        let config = CString::new(format!(
            r#"
[node]
instance_name = "{name}"
threads = 1
[network]
name = "packet-flow-fixture"
secret = "local-fixture"
[address]
ipv4 = "10.44.0.9/24"
[tun]
mode = "none"
[transport]
listen = []
[nat]
p2p = "off"
udp_punch = false
tcp_punch = false
stun = []
stun_v6 = []
stun_tcp = []
"#
        ))
        .unwrap();
        let name = CString::new(name).unwrap();
        assert_eq!(unsafe { crate::run_network_instance(config.as_ptr()) }, 0);
        let id = find_instance_id_by_name(name.to_str().unwrap()).unwrap();
        ASYNC_RUNTIME.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                while INSTANCE_MANAGER.get_instance_service(&id).is_none() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap()
        });
        let threads = (0..4)
            .map(|_| {
                let name = name.clone();
                std::thread::spawn(move || {
                    let mut handle = 0;
                    let status = unsafe {
                        open(
                            name.as_ptr(),
                            Some(discard),
                            std::ptr::null_mut(),
                            &mut handle,
                        )
                    };
                    (status, handle)
                })
            })
            .collect::<Vec<_>>();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|(status, _)| *status == 0).count(), 1);
        assert_eq!(
            results.iter().filter(|(status, _)| *status == -1).count(),
            3
        );
        let handle = results.iter().find(|(status, _)| *status == 0).unwrap().1;
        assert_eq!(close(handle), 0);
        let context = INSTANCE_MANAGER
            .get_instance_service(&id)
            .unwrap()
            .context()
            .unwrap();
        assert_eq!(context.get_tun_device_name(), None);
        let mut reopened = 0;
        assert_eq!(
            unsafe {
                open(
                    name.as_ptr(),
                    Some(discard),
                    std::ptr::null_mut(),
                    &mut reopened,
                )
            },
            0
        );
        assert_ne!(reopened, handle);
        assert_eq!(
            unsafe { crate::delete_network_instance([name.as_ptr()].as_ptr(), 1) },
            0
        );
        assert_eq!(close(reopened), -1);
        assert_eq!(context.get_tun_device_name(), None);

        // RPC lifecycle changes must release the same native callbacks.
        use lowertier::common::config::{ConfigFileControl, ConfigLoader, TomlConfigLoader};
        let directory =
            std::env::temp_dir().join(format!("lowertier-packet-flow-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("node.toml");
        let config = TomlConfigLoader::new_from_str(config.to_str().unwrap()).unwrap();
        config.set_id(uuid::Uuid::new_v4());
        std::fs::write(&path, config.dump()).unwrap();
        let id = INSTANCE_MANAGER
            .run_network_instance(
                config,
                false,
                ConfigFileControl::new(Some(path.clone()), 0u8.into()),
            )
            .unwrap();
        ASYNC_RUNTIME.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                while INSTANCE_MANAGER.get_instance_service(&id).is_none() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap()
        });
        let mut rpc_handle = 0;
        assert_eq!(
            unsafe {
                open(
                    name.as_ptr(),
                    Some(discard),
                    std::ptr::null_mut(),
                    &mut rpc_handle,
                )
            },
            0
        );
        let service = CString::new("api.control.v1.ControlPlaneV1Rpc").unwrap();
        let request =
            CString::new(serde_json::json!({"meta": {"instance_id": id.to_string()}}).to_string())
                .unwrap();
        for method in ["StopInstance", "DeleteInstance"] {
            let method = CString::new(method).unwrap();
            let mut response = std::ptr::null();
            assert_eq!(
                unsafe {
                    crate::call_json_rpc(
                        service.as_ptr(),
                        method.as_ptr(),
                        std::ptr::null(),
                        request.as_ptr(),
                        &mut response,
                    )
                },
                0
            );
            let result: serde_json::Value = serde_json::from_str(unsafe {
                std::ffi::CStr::from_ptr(response).to_str().unwrap()
            })
            .unwrap();
            crate::free_string(response);
            assert_eq!(result.get("error"), None, "{result}");
            assert!(FLOWS.get(&rpc_handle).is_none());
        }
        assert!(!path.exists());
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn packet_flow_close_waits_for_the_borrowed_output() {
        struct Callback {
            entered: mpsc::Sender<()>,
            release: std::sync::Mutex<mpsc::Receiver<()>>,
        }
        unsafe extern "C" fn hold(_: *const PacketSlice, _: usize, context: *mut c_void) -> c_int {
            let callback = unsafe { &*(context as *const Callback) };
            callback.entered.send(()).unwrap();
            callback
                .release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            0
        }
        let (entered, active) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        let callback = Box::new(Callback {
            entered,
            release: std::sync::Mutex::new(waiting),
        });
        let (peer, native) = create_ring_tunnel_pair();
        let handle = register(
            None,
            None,
            native.split(),
            hold,
            (&*callback as *const Callback) as usize,
        );
        let (_, mut sink) = peer.split();
        ASYNC_RUNTIME
            .block_on(sink.send(PacketBatch::singleton(ZCPacket::new_with_payload(
                &[0x45; 20],
            ))))
            .unwrap();
        active.recv_timeout(Duration::from_secs(3)).unwrap();
        let (finished, closed) = mpsc::channel();
        let closers = (0..2)
            .map(|_| {
                let finished = finished.clone();
                std::thread::spawn(move || finished.send(close(handle)).unwrap())
            })
            .collect::<Vec<_>>();
        assert!(closed.recv_timeout(Duration::from_millis(100)).is_err());
        release.send(()).unwrap();
        for closer in closers {
            assert_eq!(closed.recv_timeout(Duration::from_secs(3)).unwrap(), 0);
            closer.join().unwrap();
        }
    }

    #[test]
    fn packet_flow_closing_ring_wakes_credit_waiter() {
        use lowertier::tunnel::{
            TunnelError,
            ring::{RingSink, RingStream, RingTunnel},
        };
        ASYNC_RUNTIME.block_on(async {
            let tunnel = Arc::new(RingTunnel::new(8));
            let stream = RingStream::new(tunnel.clone());
            let mut sink = RingSink::new(tunnel);
            for _ in 0..8 {
                sink.send(ZCPacket::new_with_payload(&[0x45; 20]))
                    .await
                    .unwrap();
            }
            let mut blocked = Box::pin(sink.send(ZCPacket::new_with_payload(&[0x45; 20])));
            assert!(futures::poll!(blocked.as_mut()).is_pending());
            drop(stream);
            let result = tokio::time::timeout(Duration::from_secs(3), blocked)
                .await
                .unwrap();
            assert!(matches!(result, Err(TunnelError::Shutdown)));
        });
    }
}
