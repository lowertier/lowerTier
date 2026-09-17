use futures::{Sink, Stream};
use smoltcp::phy::DeviceCapabilities;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio_util::sync::{PollSendError, PollSender};

use super::device::AsyncDevice;
use crate::tunnel::{
    batch::{PacketBatch, PacketBatchIntoIter},
    packet_def::ZCPacket,
};

/// A device that send and receive packets using a channel.
pub struct ChannelDevice {
    recv: Receiver<io::Result<PacketBatch>>,
    current_batch: Option<PacketBatchIntoIter>,
    send: PollSender<ZCPacket>,
    caps: DeviceCapabilities,
}

pub type ChannelDeviceNewRet = (
    ChannelDevice,
    Sender<io::Result<PacketBatch>>,
    Receiver<ZCPacket>,
);

impl ChannelDevice {
    /// Make a new `ChannelDevice` with the given `recv` and `send` channels.
    ///
    /// The `caps` is used to determine the device capabilities. `DeviceCapabilities::max_transmission_unit` must be set.
    pub fn new(caps: DeviceCapabilities) -> ChannelDeviceNewRet {
        let (tx1, rx1) = channel(1000);
        let (tx2, rx2) = channel(1000);
        (
            ChannelDevice {
                send: PollSender::new(tx1),
                recv: rx2,
                current_batch: None,
                caps,
            },
            tx2,
            rx1,
        )
    }
}

impl Stream for ChannelDevice {
    type Item = io::Result<ZCPacket>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(packet) = self
                .current_batch
                .as_mut()
                .and_then(PacketBatchIntoIter::next)
            {
                return Poll::Ready(Some(Ok(packet)));
            }
            self.current_batch = None;
            match self.recv.poll_recv(cx) {
                Poll::Ready(Some(Ok(batch))) => self.current_batch = Some(batch.into_iter()),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn map_err(e: PollSendError<ZCPacket>) -> io::Error {
    io::Error::other(e)
}

impl Sink<ZCPacket> for ChannelDevice {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send.poll_reserve(cx).map_err(map_err)
    }

    fn start_send(mut self: Pin<&mut Self>, item: ZCPacket) -> Result<(), Self::Error> {
        self.send.send_item(item).map_err(map_err)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send.poll_reserve(cx).map_err(map_err)
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncDevice for ChannelDevice {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.caps
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};

    use super::*;
    use crate::tunnel::{batch::PacketBatch, packet_def::ZCPacket};
}
