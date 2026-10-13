//! Preserve peer TLS authentication across a WebSocket-terminating proxy.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_websockets::{Message, WebSocketStream};

use super::*;
use crate::tunnel::common::{FramedReader, FramedWriter};

pub(super) const SUBPROTOCOL: &str = "lowertier-tls-v1";
const ALPN: &[u8] = b"lowertier-wss-cdn/1";
// TLS records fit in this bound. Writes can stop at any byte boundary.
const WRITE_CHUNK_BYTES: usize = 32 * 1024;

struct WebSocketIo<S> {
    socket: WebSocketStream<S>,
    buffered: Bytes,
    closed: bool,
}

impl<S> WebSocketIo<S> {
    fn new(socket: WebSocketStream<S>) -> Self {
        Self {
            socket,
            buffered: Bytes::new(),
            closed: false,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.buffered.is_empty() {
                let count = out.remaining().min(self.buffered.len());
                out.put_slice(&self.buffered[..count]);
                self.buffered.advance(count);
                return Poll::Ready(Ok(()));
            }
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.socket).poll_next(cx)) {
                Some(Ok(message)) if message.is_binary() => {
                    self.buffered = message.into_payload().into()
                }
                Some(Ok(message)) if message.is_close() => self.closed = true,
                Some(Ok(message)) if message.is_text() => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "CDN TLS requires binary WebSocket messages",
                    )));
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => self.closed = true,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocketIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.socket).poll_ready(cx)).map_err(io::Error::other)?;
        let count = data.len().min(WRITE_CHUNK_BYTES);
        Pin::new(&mut self.socket)
            .start_send(Message::binary(bytes::BytesMut::from(&data[..count])))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

fn wrap<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    info: TunnelInfo,
    binding: TransportBinding,
) -> Box<dyn Tunnel> {
    let (read, write) = tokio::io::split(stream);
    Box::new(TunnelWrapper::new_with_transport_binding(
        FramedReader::new_with_initial_capacity(read, MAX_WS_MESSAGE_BYTES, 4096),
        FramedWriter::new(write),
        Some(info),
        Some(binding),
    ))
}

pub(super) async fn accept<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: WebSocketStream<S>,
    info: TunnelInfo,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let mut config = wss_server_config()?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    let stream = TlsAcceptor::from(Arc::new(config))
        .accept(WebSocketIo::new(socket))
        .await?;
    let binding = derive_wss_binding(|output| {
        stream
            .get_ref()
            .1
            .export_keying_material(
                output,
                WSS_TRANSPORT_BINDING_LABEL,
                Some(WSS_TRANSPORT_BINDING_CONTEXT),
            )
            .map(|_| ())
    })?;
    Ok(wrap(stream, info, binding))
}

pub(super) async fn connect<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    socket: WebSocketStream<S>,
    info: TunnelInfo,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    // Noise authenticates this endpoint and binds its transcript to inner TLS.
    // The outer CDN TLS connection still requires a valid public certificate.
    let stream = super::super::browser_tls::connect(
        WebSocketIo::new(socket),
        "challenges.cloudflare.com",
        &[ALPN],
        false,
    )
    .await?;
    let binding = derive_wss_binding(|output| {
        stream
            .get_ref()
            .1
            .export_keying_material(
                output,
                WSS_TRANSPORT_BINDING_LABEL,
                Some(WSS_TRANSPORT_BINDING_CONTEXT),
            )
            .map(|_| ())
    })?;
    Ok(wrap(stream, info, binding))
}
