use async_ringbuf::{AsyncHeapCons, AsyncHeapProd, AsyncHeapRb, traits::*};
use crossbeam::atomic::AtomicCell;
use std::{
    collections::HashMap,
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use async_trait::async_trait;
use futures::{Sink, SinkExt, Stream, StreamExt};
use once_cell::sync::Lazy;

use tokio::sync::{
    OwnedSemaphorePermit, Semaphore, TryAcquireError,
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};

use uuid::Uuid;

use crate::tunnel::{FromUrl, IpVersion, SinkError, SinkItem};

use super::{
    StreamItem, Tunnel, TunnelConnector, TunnelError, TunnelInfo, TunnelListener,
    batch::{MAX_PACKET_BATCH_SIZE, PacketBatch},
    build_url_from_socket_addr,
    common::TunnelWrapper,
};

pub static RING_TUNNEL_CAP: usize = 128;
static RING_TUNNEL_RESERVED_CAP: usize = 4;

type RingLock = parking_lot::Mutex<()>;

struct RingItem {
    batch: PacketBatch,
    _packet_permits: OwnedSemaphorePermit,
}

pub struct RingTunnel {
    id: Uuid,

    ring_cons_impl: AtomicCell<Option<AsyncHeapCons<RingItem>>>,
    ring_prod_impl: AtomicCell<Option<AsyncHeapProd<RingItem>>>,
    packet_permits: Arc<Semaphore>,
}

impl RingTunnel {
    fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn new(cap: usize) -> Self {
        let id = Uuid::new_v4();
        let capacity = std::cmp::max(RING_TUNNEL_RESERVED_CAP * 2, cap);
        let ring_impl = AsyncHeapRb::new(capacity);
        let (ring_prod_impl, ring_cons_impl) = ring_impl.split();
        Self {
            id,
            ring_cons_impl: AtomicCell::new(Some(ring_cons_impl)),
            ring_prod_impl: AtomicCell::new(Some(ring_prod_impl)),
            packet_permits: Arc::new(Semaphore::new(capacity)),
        }
    }

    pub fn new_with_id(id: Uuid, cap: usize) -> Self {
        let mut ret = Self::new(cap);
        ret.id = id;
        ret
    }
}

impl Debug for RingTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingTunnel").field("id", &self.id).finish()
    }
}

pub struct RingStream {
    id: Uuid,
    ring_cons_impl: AsyncHeapCons<RingItem>,
    pending: Option<smallvec::IntoIter<[SinkItem; 4]>>,
}

impl RingStream {
    pub fn new(tunnel: Arc<RingTunnel>) -> Self {
        Self {
            id: tunnel.id,
            ring_cons_impl: tunnel.ring_cons_impl.take().unwrap(),
            pending: None,
        }
    }

    pub fn try_recv(&mut self) -> Option<SinkItem> {
        if let Some(packet) = self.pending.as_mut().and_then(Iterator::next) {
            return Some(packet);
        }
        self.pending = None;
        let RingItem { batch, .. } = self.ring_cons_impl.try_pop()?;
        let mut packets = batch.into_iter();
        let packet = packets.next();
        self.pending = Some(packets);
        packet
    }

    pub fn try_recv_batch(&mut self) -> Option<PacketBatch> {
        if let Some(mut pending) = self.pending.take() {
            let mut batch = PacketBatch::new();
            for packet in &mut pending {
                batch
                    .try_push(packet)
                    .expect("pending ring vector remains bounded");
            }
            if !batch.is_empty() {
                return Some(batch);
            }
        }
        self.ring_cons_impl.try_pop().map(|item| item.batch)
    }

    pub async fn recv_batch(&mut self) -> Option<PacketBatch> {
        if let Some(batch) = self.try_recv_batch() {
            return Some(batch);
        }
        self.ring_cons_impl.next().await.map(|item| item.batch)
    }
}

impl Stream for RingStream {
    type Item = StreamItem;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let self_mut = self.get_mut();
        if let Some(packet) = self_mut.pending.as_mut().and_then(Iterator::next) {
            return Poll::Ready(Some(Ok(packet)));
        }
        self_mut.pending = None;
        let ret = ready!(self_mut.ring_cons_impl.poll_next_unpin(cx));
        match ret {
            Some(item) => {
                let mut packets = item.batch.into_iter();
                let packet = packets.next().expect("empty ring vectors are never queued");
                self_mut.pending = Some(packets);
                Poll::Ready(Some(Ok(packet)))
            }
            None => Poll::Ready(None),
        }
    }
}

impl Debug for RingStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingStream")
            .field("id", &self.id)
            .field("len", &self.ring_cons_impl.base().occupied_len())
            .field("cap", &self.ring_cons_impl.base().capacity())
            .finish()
    }
}

pub struct RingSink {
    id: Uuid,
    ring_prod_impl: AsyncHeapProd<RingItem>,
    packet_permits: Arc<Semaphore>,
    permit_wait: Option<Pin<Box<dyn Future<Output = OwnedSemaphorePermit> + Send + Sync>>>,
    ready_permit: Option<OwnedSemaphorePermit>,
    pending: PacketBatch,
    pending_permits: Option<OwnedSemaphorePermit>,
}

impl RingSink {
    pub fn new(tunnel: Arc<RingTunnel>) -> Self {
        Self {
            id: tunnel.id,
            ring_prod_impl: tunnel.ring_prod_impl.take().unwrap(),
            packet_permits: tunnel.packet_permits.clone(),
            permit_wait: None,
            ready_permit: None,
            pending: PacketBatch::new(),
            pending_permits: None,
        }
    }

    fn take_pending(&mut self) -> Option<RingItem> {
        if self.pending.is_empty() {
            return None;
        }
        Some(RingItem {
            batch: std::mem::take(&mut self.pending),
            _packet_permits: self
                .pending_permits
                .take()
                .expect("every pending packet owns a ring credit"),
        })
    }

    fn restore_pending(&mut self, item: RingItem) {
        self.pending = item.batch;
        self.pending_permits = Some(item._packet_permits);
    }

    fn try_commit_pending(&mut self) -> Result<(), ()> {
        let Some(item) = self.take_pending() else {
            return Ok(());
        };
        match self.ring_prod_impl.try_push(item) {
            Ok(()) => Ok(()),
            Err(item) => {
                self.restore_pending(item);
                Err(())
            }
        }
    }

    fn poll_packet_permit(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        if self.ready_permit.is_some() {
            return Poll::Ready(Ok(()));
        }
        if self.permit_wait.is_none() {
            match self.packet_permits.clone().try_acquire_owned() {
                Ok(permit) => {
                    self.ready_permit = Some(permit);
                    return Poll::Ready(Ok(()));
                }
                Err(TryAcquireError::Closed) => return Poll::Ready(Err(TunnelError::Shutdown)),
                Err(TryAcquireError::NoPermits) => {}
            }
            let permits = self.packet_permits.clone();
            self.permit_wait = Some(Box::pin(async move {
                permits
                    .acquire_owned()
                    .await
                    .expect("ring packet semaphore is never closed")
            }));
        }
        let permit = ready!(
            self.permit_wait
                .as_mut()
                .expect("permit future was installed")
                .as_mut()
                .poll(cx)
        );
        self.permit_wait = None;
        self.ready_permit = Some(permit);
        Poll::Ready(Ok(()))
    }

    fn start_send_pending(&mut self) -> Result<(), SinkError> {
        let item = self.take_pending().expect("pending batch is not empty");
        self.ring_prod_impl
            .start_send_unpin(item)
            .map_err(|_| TunnelError::Shutdown)
    }

    pub fn try_send(&mut self, item: SinkItem) -> Result<(), SinkItem> {
        if self.try_commit_pending().is_err() {
            return Err(item);
        }
        self.try_send_batch(PacketBatch::singleton(item))
            .map_err(|batch| batch.pop_singleton().expect("scalar ring job"))
    }

    pub fn try_send_batch(&mut self, batch: PacketBatch) -> Result<(), PacketBatch> {
        if batch.is_empty() {
            return Ok(());
        }
        let base = self.ring_prod_impl.base();
        if base.occupied_len() >= base.capacity().get() - RING_TUNNEL_RESERVED_CAP {
            return Err(batch);
        }
        let Ok(permit_count) = u32::try_from(batch.len()) else {
            return Err(batch);
        };
        let Ok(packet_permits) = self
            .packet_permits
            .clone()
            .try_acquire_many_owned(permit_count)
        else {
            return Err(batch);
        };
        self.ring_prod_impl
            .try_push(RingItem {
                batch,
                _packet_permits: packet_permits,
            })
            .map_err(|item| item.batch)
    }

    pub fn force_send(&mut self, item: SinkItem) -> Result<(), SinkItem> {
        if self.try_commit_pending().is_err() {
            return Err(item);
        }
        self.force_send_batch(PacketBatch::singleton(item))
            .map_err(|batch| batch.pop_singleton().expect("scalar ring job"))
    }

    pub fn force_send_batch(&mut self, batch: PacketBatch) -> Result<(), PacketBatch> {
        if batch.is_empty() {
            return Ok(());
        }
        let Ok(permit_count) = u32::try_from(batch.len()) else {
            return Err(batch);
        };
        let Ok(packet_permits) = self
            .packet_permits
            .clone()
            .try_acquire_many_owned(permit_count)
        else {
            return Err(batch);
        };
        self.ring_prod_impl
            .try_push(RingItem {
                batch,
                _packet_permits: packet_permits,
            })
            .map_err(|item| item.batch)
    }
}

impl Sink<SinkItem> for RingSink {
    type Error = SinkError;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let self_mut = self.get_mut();
        if self_mut.pending.len() == MAX_PACKET_BATCH_SIZE {
            ready!(self_mut.ring_prod_impl.poll_ready_unpin(cx))
                .map_err(|_| TunnelError::Shutdown)?;
            self_mut.start_send_pending()?;
        }
        self_mut.poll_packet_permit(cx)
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        let self_mut = self.get_mut();
        let permit = self_mut
            .ready_permit
            .take()
            .expect("start_send follows a successful poll_ready");
        if let Some(pending_permits) = self_mut.pending_permits.as_mut() {
            pending_permits.merge(permit);
        } else {
            self_mut.pending_permits = Some(permit);
        }
        self_mut
            .pending
            .try_push(item)
            .map_err(|_| TunnelError::BufferFull)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let self_mut = self.get_mut();
        if !self_mut.pending.is_empty() {
            ready!(self_mut.ring_prod_impl.poll_ready_unpin(cx))
                .map_err(|_| TunnelError::Shutdown)?;
            self_mut.start_send_pending()?;
        }
        let ret = ready!(self_mut.ring_prod_impl.poll_flush_unpin(cx));
        Poll::Ready(ret.map_err(|_| TunnelError::Shutdown))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let self_mut = self.get_mut();
        if !self_mut.pending.is_empty() {
            ready!(self_mut.ring_prod_impl.poll_ready_unpin(cx))
                .map_err(|_| TunnelError::Shutdown)?;
            self_mut.start_send_pending()?;
        }
        let ret = ready!(self_mut.ring_prod_impl.poll_close_unpin(cx));
        Poll::Ready(ret.map_err(|_| TunnelError::Shutdown))
    }
}

impl Debug for RingSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingSink")
            .field("id", &self.id)
            .field("len", &self.ring_prod_impl.base().occupied_len())
            .field("cap", &self.ring_prod_impl.base().capacity())
            .finish()
    }
}

struct Connection {
    client: Arc<RingTunnel>,
    server: Arc<RingTunnel>,
}

type ConnectionMap = HashMap<uuid::Uuid, UnboundedSender<Arc<Connection>>>;

static CONNECTION_MAP: Lazy<Arc<std::sync::Mutex<ConnectionMap>>> =
    Lazy::new(|| Arc::new(std::sync::Mutex::new(HashMap::new())));

#[derive(Debug)]
pub struct RingTunnelListener {
    listener_addr: url::Url,
    conn_sender: UnboundedSender<Arc<Connection>>,
    conn_receiver: UnboundedReceiver<Arc<Connection>>,

    key_in_conn_map: Option<uuid::Uuid>,
}

impl RingTunnelListener {
    pub fn new(key: url::Url) -> Self {
        let (conn_sender, conn_receiver) = unbounded_channel();
        RingTunnelListener {
            listener_addr: key,
            conn_sender,
            conn_receiver,
            key_in_conn_map: None,
        }
    }
}

fn get_tunnel_for_client(conn: Arc<Connection>) -> impl Tunnel {
    TunnelWrapper::new(
        RingStream::new(conn.client.clone()),
        RingSink::new(conn.server.clone()),
        Some(TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: Some(build_url_from_socket_addr(&conn.client.id.into(), "ring").into()),
            remote_addr: Some(build_url_from_socket_addr(&conn.server.id.into(), "ring").into()),
            resolved_remote_addr: Some(
                build_url_from_socket_addr(&conn.server.id.into(), "ring").into(),
            ),
        }),
    )
}

fn get_tunnel_for_server(conn: Arc<Connection>) -> impl Tunnel {
    TunnelWrapper::new(
        RingStream::new(conn.server.clone()),
        RingSink::new(conn.client.clone()),
        Some(TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: Some(build_url_from_socket_addr(&conn.server.id.into(), "ring").into()),
            remote_addr: Some(build_url_from_socket_addr(&conn.client.id.into(), "ring").into()),
            resolved_remote_addr: Some(
                build_url_from_socket_addr(&conn.client.id.into(), "ring").into(),
            ),
        }),
    )
}

impl RingTunnelListener {
    async fn get_addr(&self) -> Result<Uuid, TunnelError> {
        Uuid::from_url(self.listener_addr.clone(), IpVersion::Both).await
    }
}

#[async_trait]
impl TunnelListener for RingTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        tracing::info!("listen new conn of key: {}", self.listener_addr);
        let addr = self.get_addr().await?;
        CONNECTION_MAP
            .lock()
            .unwrap()
            .insert(addr, self.conn_sender.clone());
        self.key_in_conn_map = Some(addr);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        tracing::info!("waiting accept new conn of key: {}", self.listener_addr);
        let my_addr = self.get_addr().await?;
        if let Some(conn) = self.conn_receiver.recv().await {
            if conn.server.id == my_addr {
                tracing::info!("accept new conn of key: {}", self.listener_addr);
                return Ok(Box::new(get_tunnel_for_server(conn)));
            } else {
                tracing::error!(?conn.server.id, ?my_addr, "got new conn with wrong id");
                return Err(TunnelError::InternalError(
                    "accept got wrong ring server id".to_owned(),
                ));
            }
        }

        return Err(TunnelError::InternalError(
            "conn receiver stopped".to_owned(),
        ));
    }

    fn local_url(&self) -> url::Url {
        self.listener_addr.clone()
    }
}

impl Drop for RingTunnelListener {
    fn drop(&mut self) {
        if let Some(addr) = self.key_in_conn_map {
            CONNECTION_MAP.lock().unwrap().remove(&addr);
        }
    }
}

pub struct RingTunnelConnector {
    remote_addr: url::Url,
}

impl RingTunnelConnector {
    pub fn new(remote_addr: url::Url) -> Self {
        RingTunnelConnector { remote_addr }
    }
}

#[async_trait]
impl TunnelConnector for RingTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let remote_addr = Uuid::from_url(self.remote_addr.clone(), IpVersion::Both).await?;
        let entry = CONNECTION_MAP
            .lock()
            .unwrap()
            .get(&remote_addr)
            .unwrap()
            .clone();
        tracing::info!("connecting");
        let conn = Arc::new(Connection {
            client: Arc::new(RingTunnel::new(RING_TUNNEL_CAP)),
            server: Arc::new(RingTunnel::new_with_id(remote_addr, RING_TUNNEL_CAP)),
        });
        entry
            .send(conn.clone())
            .map_err(|_| TunnelError::InternalError("send conn to listner failed".to_owned()))?;
        Ok(Box::new(get_tunnel_for_client(conn)))
    }

    fn remote_url(&self) -> url::Url {
        self.remote_addr.clone()
    }
}

pub fn create_ring_tunnel_pair() -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
    let conn = Arc::new(Connection {
        client: Arc::new(RingTunnel::new(RING_TUNNEL_CAP)),
        server: Arc::new(RingTunnel::new(RING_TUNNEL_CAP)),
    });
    (
        Box::new(get_tunnel_for_server(conn.clone())),
        Box::new(get_tunnel_for_client(conn)),
    )
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use tokio::time::timeout;

    use crate::tunnel::common::tests::{_tunnel_bench, _tunnel_pingpong};

    use super::*;

    #[tokio::test]
    async fn ring_pingpong() {
        let id: url::Url = format!("ring://{}", Uuid::new_v4()).parse().unwrap();
        let listener = RingTunnelListener::new(id.clone());
        let connector = RingTunnelConnector::new(id.clone());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ring_bench() {
        let id: url::Url = format!("ring://{}", Uuid::new_v4()).parse().unwrap();
        let listener = RingTunnelListener::new(id.clone());
        let connector = RingTunnelConnector::new(id);
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn ring_close() {
        let (stunnel, ctunnel) = create_ring_tunnel_pair();
        drop(stunnel);

        let mut stream = ctunnel.split().0;
        let ret = stream.next().await;
        assert!(ret.as_ref().is_none(), "expect none, got {:?}", ret);
    }

    #[tokio::test]
    async fn abort_ring_stream() {
        let (_stunnel, ctunnel) = create_ring_tunnel_pair();
        let mut stream = ctunnel.split().0;
        let task = tokio::spawn(async move {
            let _ = stream.next().await;
        });
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        task.abort();
        let _ = tokio::join!(task);
    }

    #[tokio::test]
    async fn ring_stream_recv_timeout() {
        let (_stunnel, ctunnel) = create_ring_tunnel_pair();
        let mut stream = ctunnel.split().0;
        let _ = timeout(tokio::time::Duration::from_millis(10), stream.next()).await;
    }

    #[tokio::test]
    async fn ring_stream_drains_only_already_ready_packets() {
        let ring = Arc::new(RingTunnel::new(8));
        let mut sink = RingSink::new(ring.clone());
        let mut stream = RingStream::new(ring);
        sink.send(crate::tunnel::packet_def::ZCPacket::new_with_payload(
            b"one",
        ))
        .await
        .unwrap();
        sink.send(crate::tunnel::packet_def::ZCPacket::new_with_payload(
            b"two",
        ))
        .await
        .unwrap();

        assert_eq!(stream.next().await.unwrap().unwrap().payload(), b"one");
        assert_eq!(stream.try_recv().unwrap().payload(), b"two");
        assert!(stream.try_recv().is_none());
    }

    #[tokio::test]
    async fn ring_preserves_a_bounded_vector_as_one_queue_job() {
        let ring = Arc::new(RingTunnel::new(8));
        let mut sink = RingSink::new(ring.clone());
        let mut stream = RingStream::new(ring);
        let mut batch = crate::tunnel::batch::PacketBatch::new();
        for value in 0_u8..4 {
            batch
                .try_push(crate::tunnel::packet_def::ZCPacket::new_with_payload(&[
                    value,
                ]))
                .unwrap();
        }

        sink.try_send_batch(batch).unwrap();
        let received = stream.try_recv_batch().unwrap();

        assert_eq!(received.len(), 4);
        assert_eq!(
            received
                .iter()
                .map(|packet| packet.payload()[0])
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn ring_capacity_is_bounded_by_packets_not_only_vector_jobs() {
        let ring = Arc::new(RingTunnel::new(8));
        let mut sink = RingSink::new(ring.clone());
        let _stream = RingStream::new(ring);
        let make_batch = |len: usize| {
            let mut batch = PacketBatch::new();
            for value in 0..len {
                batch
                    .try_push(crate::tunnel::packet_def::ZCPacket::new_with_payload(&[
                        value as u8,
                    ]))
                    .unwrap();
            }
            batch
        };

        sink.try_send_batch(make_batch(5)).unwrap();
        let rejected = sink.try_send_batch(make_batch(4)).unwrap_err();

        assert_eq!(rejected.len(), 4);
    }
}
