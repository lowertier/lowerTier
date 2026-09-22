use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct TapMac(AtomicU64);

impl TapMac {
    pub(super) fn new(mac: [u8; 6]) -> Self {
        Self(AtomicU64::new(Self::encode(mac)))
    }

    fn encode(mac: [u8; 6]) -> u64 {
        let mut bytes = [0; 8];
        bytes[..6].copy_from_slice(&mac);
        u64::from_ne_bytes(bytes)
    }

    pub(super) fn load(&self) -> [u8; 6] {
        self.0.load(Ordering::Relaxed).to_ne_bytes()[..6]
            .try_into()
            .unwrap()
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn store(&self, mac: [u8; 6]) {
        self.0.store(Self::encode(mac), Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
pub(super) mod linux {
    use std::{ffi::CString, io};

    use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
    use netlink_packet_route::RouteNetlinkMessage;
    use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
    use nix::libc;
    use tokio::io::unix::AsyncFd;

    pub(crate) struct LinkMonitor {
        socket: AsyncFd<Socket>,
        ifindex: u32,
    }

    impl LinkMonitor {
        pub(crate) fn new(ifname: &str) -> io::Result<Self> {
            let name = CString::new(ifname)?;
            let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if ifindex == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut socket = Socket::new(NETLINK_ROUTE)?;
            socket.bind(&SocketAddr::new(0, libc::RTMGRP_LINK as u32))?;
            socket.set_non_blocking(true)?;
            Ok(Self {
                socket: AsyncFd::new(socket)?,
                ifindex,
            })
        }

        pub(crate) async fn changed(&self) -> io::Result<()> {
            loop {
                let mut ready = self.socket.readable().await?;
                let received = ready.try_io(|socket| socket.get_ref().recv_from_full());
                let (bytes, sender) = match received {
                    Err(_) => continue,
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    // An overflow loses events. The caller must read the current MAC again.
                    Ok(Err(error)) if error.raw_os_error() == Some(libc::ENOBUFS) => return Ok(()),
                    Ok(result) => result?,
                };
                if sender.port_number() == 0 {
                    match contains_link_event(&bytes, self.ifindex) {
                        Ok(false) => {}
                        Ok(true) => return Ok(()),
                        Err(error) => {
                            tracing::warn!(?error, "cannot decode link event; refreshing TAP MAC");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    fn contains_link_event(mut bytes: &[u8], ifindex: u32) -> io::Result<bool> {
        while !bytes.is_empty() {
            if bytes.len() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short netlink header",
                ));
            }
            let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
            if length < 16 || length > bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid netlink length",
                ));
            }
            let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&bytes[..length])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            match message.payload {
                NetlinkPayload::InnerMessage(
                    RouteNetlinkMessage::NewLink(link) | RouteNetlinkMessage::DelLink(link),
                ) if link.header.index == ifindex => return Ok(true),
                NetlinkPayload::Overrun(_) => return Ok(true),
                NetlinkPayload::Error(error) if error.code.is_some() => return Err(error.to_io()),
                _ => {}
            }
            let aligned = (length + 3) & !3;
            bytes = bytes.get(aligned..).unwrap_or_default();
        }
        Ok(false)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use netlink_packet_route::link::LinkMessage;

        fn link_event(index: u32) -> Vec<u8> {
            let mut link = LinkMessage::default();
            link.header.index = index;
            let mut message = NetlinkMessage::from(RouteNetlinkMessage::NewLink(link));
            message.finalize();
            let mut bytes = vec![0; message.buffer_len()];
            message.serialize(&mut bytes);
            bytes
        }

        #[test]
        fn finds_target_interface_after_an_unrelated_event() {
            let mut bytes = link_event(3);
            assert!(!contains_link_event(&bytes, 7).unwrap());
            bytes.extend_from_slice(&link_event(7));
            assert!(contains_link_event(&bytes, 7).unwrap());
        }

        #[test]
        fn rejects_truncated_link_events() {
            let mut bytes = link_event(7);
            bytes.pop();
            assert!(contains_link_event(&bytes, 7).is_err());
        }
    }
}
