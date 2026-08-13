#[cfg(feature = "zstd")]
use anyhow::Context;
#[cfg(feature = "zstd")]
use dashmap::DashMap;
#[cfg(feature = "zstd")]
use std::cell::RefCell;
#[cfg(feature = "zstd")]
use zstd::bulk;

use zerocopy::{AsBytes as _, FromBytes as _};

use crate::tunnel::packet_def::{
    COMPRESSOR_TAIL_SIZE, CompressorAlgo, CompressorTail, PEER_MANAGER_HEADER_SIZE, ZCPacket,
};

type Error = anyhow::Error;

/// Bound the logical payload to the largest reliable frame accepted by QUIC.
pub(crate) const MAX_LOGICAL_OVERLAY_PAYLOAD_BYTES: usize = 64 * 1024 - PEER_MANAGER_HEADER_SIZE;

pub trait Compressor {
    fn compress(&self, packet: &mut ZCPacket, compress_algo: CompressorAlgo) -> Result<(), Error>;
    fn decompress(&self, packet: &mut ZCPacket) -> Result<(), Error>;
}

pub struct DefaultCompressor {}

impl Default for DefaultCompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultCompressor {
    pub fn new() -> Self {
        DefaultCompressor {}
    }

    pub fn compress_raw(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo,
    ) -> Result<Vec<u8>, Error> {
        match compress_algo {
            #[cfg(feature = "zstd")]
            CompressorAlgo::ZstdDefault => CTX_MAP.with(|map_cell| {
                let map = map_cell.borrow();
                let mut ctx_entry = map.entry(compress_algo).or_default();
                ctx_entry.compress(data).with_context(|| {
                    format!(
                        "Failed to compress data with algorithm: {:?}",
                        compress_algo
                    )
                })
            }),
            CompressorAlgo::None => Ok(data.to_vec()),
        }
    }

    pub fn decompress_raw(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo,
    ) -> Result<Vec<u8>, Error> {
        match compress_algo {
            #[cfg(feature = "zstd")]
            CompressorAlgo::ZstdDefault => DCTX_MAP.with(|map_cell| {
                let map = map_cell.borrow();
                let mut ctx_entry = map.entry(compress_algo).or_default();
                for i in 1..=5 {
                    let mut len = data.len() * 2usize.pow(i);
                    if i == 5 && len < 64 * 1024 {
                        len = 64 * 1024; // Ensure a minimum buffer size
                    }
                    match ctx_entry.decompress(data, len) {
                        Ok(buf) => return Ok(buf),
                        Err(e) if e.to_string().contains("buffer is too small") => {
                            continue; // Try with a larger buffer
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                Err(anyhow::anyhow!(
                    "Failed to decompress data after multiple attempts with algorithm: {:?}",
                    compress_algo
                ))
            }),
            CompressorAlgo::None => Ok(data.to_vec()),
        }
    }

    /// Decompress one packet into the exact declared logical payload length.
    pub fn decompress_raw_exact(
        &self,
        data: &[u8],
        compress_algo: CompressorAlgo,
        expected_len: usize,
    ) -> Result<Vec<u8>, Error> {
        if expected_len > MAX_LOGICAL_OVERLAY_PAYLOAD_BYTES {
            anyhow::bail!(
                "declared logical payload exceeds limit: {} > {}",
                expected_len,
                MAX_LOGICAL_OVERLAY_PAYLOAD_BYTES
            );
        }
        match compress_algo {
            #[cfg(feature = "zstd")]
            CompressorAlgo::ZstdDefault => DCTX_MAP.with(|map_cell| {
                let map = map_cell.borrow();
                let mut ctx_entry = map.entry(compress_algo).or_default();
                let buf = ctx_entry
                    .decompress(data, expected_len)
                    .with_context(|| "failed to decompress packet into declared length")?;
                if buf.len() != expected_len {
                    anyhow::bail!(
                        "decompressed length mismatch: {} != {}",
                        buf.len(),
                        expected_len
                    );
                }
                Ok(buf)
            }),
            CompressorAlgo::None => {
                if data.len() != expected_len {
                    anyhow::bail!(
                        "uncompressed length mismatch: {} != {}",
                        data.len(),
                        expected_len
                    );
                }
                Ok(data.to_vec())
            }
        }
    }
}

impl Compressor for DefaultCompressor {
    fn compress(
        &self,
        zc_packet: &mut ZCPacket,
        compress_algo: CompressorAlgo,
    ) -> Result<(), Error> {
        let logical_len = zc_packet.payload_len();
        if logical_len > MAX_LOGICAL_OVERLAY_PAYLOAD_BYTES {
            anyhow::bail!(
                "logical payload exceeds the 64 KiB QUIC frame limit: {} > {}",
                logical_len,
                MAX_LOGICAL_OVERLAY_PAYLOAD_BYTES
            );
        }
        if matches!(compress_algo, CompressorAlgo::None) {
            return Ok(());
        }

        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_compressed() {
            return Ok(());
        }

        let tail = CompressorTail::new(compress_algo);
        let buf = self.compress_raw(zc_packet.payload(), compress_algo)?;

        if buf.len() + COMPRESSOR_TAIL_SIZE > pm_header.len.get() as usize {
            // Compressed data is larger than original data, don't compress
            return Ok(());
        }

        zc_packet
            .mut_peer_manager_header()
            .unwrap()
            .set_compressed(true);

        let payload_offset = zc_packet.payload_offset();
        zc_packet
            .mut_inner_preserving_flow_hash()
            .truncate(payload_offset);
        zc_packet
            .mut_inner_preserving_flow_hash()
            .extend_from_slice(&buf);
        zc_packet
            .mut_inner_preserving_flow_hash()
            .extend_from_slice(tail.as_bytes());

        Ok(())
    }

    fn decompress(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_compressed() {
            return Ok(());
        }

        let declared_len = pm_header.len.get() as usize;
        if declared_len > MAX_LOGICAL_OVERLAY_PAYLOAD_BYTES {
            return Err(anyhow::anyhow!(
                "declared logical payload exceeds limit: {} > {}",
                declared_len,
                MAX_LOGICAL_OVERLAY_PAYLOAD_BYTES
            ));
        }

        let payload_len = zc_packet.payload().len();
        if payload_len < COMPRESSOR_TAIL_SIZE {
            return Err(anyhow::anyhow!("Packet too short: {}", payload_len));
        }

        let text_len = payload_len - COMPRESSOR_TAIL_SIZE;
        if text_len > declared_len {
            return Err(anyhow::anyhow!(
                "compressed payload exceeds declared logical length: {} > {}",
                text_len,
                declared_len
            ));
        }

        let tail = CompressorTail::ref_from_suffix(zc_packet.payload())
            .unwrap()
            .clone();

        let algo = tail
            .get_algo()
            .ok_or(anyhow::anyhow!("Unknown algo: {:?}", tail))?;

        let buf =
            self.decompress_raw_exact(&zc_packet.payload()[..text_len], algo, declared_len)?;

        if buf.len() != declared_len {
            anyhow::bail!(
                "Decompressed length mismatch: decompressed len {} != pm header len {}",
                buf.len(),
                declared_len
            );
        }

        zc_packet
            .mut_peer_manager_header()
            .unwrap()
            .set_compressed(false);

        let payload_offset = zc_packet.payload_offset();
        zc_packet
            .mut_inner_preserving_flow_hash()
            .truncate(payload_offset);
        zc_packet
            .mut_inner_preserving_flow_hash()
            .extend_from_slice(&buf);

        Ok(())
    }
}

#[cfg(feature = "zstd")]
thread_local! {
    static CTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Compressor<'static>>> = RefCell::new(DashMap::new());
    static DCTX_MAP: RefCell<DashMap<CompressorAlgo, bulk::Decompressor<'static>>> = RefCell::new(DashMap::new());
}

#[cfg(test)]
mod synchronous_tests {
    use super::{Compressor, DefaultCompressor, MAX_LOGICAL_OVERLAY_PAYLOAD_BYTES};
    use crate::tunnel::packet_def::{CompressorAlgo, PacketType, ZCPacket};

    #[test]
    fn uncompressed_packet_check_is_synchronous() {
        fn assert_result(_: Result<(), anyhow::Error>) {}

        let mut packet = ZCPacket::new_with_payload(b"plain");
        packet.fill_peer_manager_hdr(1, 2, 1);

        assert_result(DefaultCompressor::new().decompress(&mut packet));
    }

    #[test]
    fn compress_rejects_payload_above_quic_frame_limit() {
        let payload = vec![0_u8; MAX_LOGICAL_OVERLAY_PAYLOAD_BYTES + 1];
        let mut packet = ZCPacket::new_with_payload(&payload);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);

        let error = DefaultCompressor::new()
            .compress(&mut packet, CompressorAlgo::None)
            .expect_err("an oversized logical payload must fail before sending");
        assert!(
            error
                .to_string()
                .contains("logical payload exceeds the 64 KiB QUIC frame limit")
        );
    }
}

#[cfg(all(test, feature = "zstd"))]
pub mod tests {
    use super::*;
    use crate::peers::flow::stamp_packet_flow;

    #[tokio::test]
    async fn test_compress() {
        let text = b"12345670000000000000000000";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);
        let flow = stamp_packet_flow(&mut packet);

        let compressor = DefaultCompressor {};

        println!(
            "Uncompressed packet: {:?}, len: {}",
            packet,
            packet.payload_len()
        );

        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .unwrap();
        assert_eq!(packet.flow_hash(), Some(flow.hash));
        println!(
            "Compressed packet: {:?}, len: {}",
            packet,
            packet.payload_len()
        );
        assert!(packet.peer_manager_header().unwrap().is_compressed());

        compressor.decompress(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert_eq!(packet.flow_hash(), Some(flow.hash));
        assert!(!packet.peer_manager_header().unwrap().is_compressed());
    }

    #[tokio::test]
    async fn test_short_text_compress() {
        let text = b"1234";
        let mut packet = ZCPacket::new_with_payload(text);
        packet.fill_peer_manager_hdr(0, 0, 0);

        let compressor = DefaultCompressor {};

        // short text can't be compressed
        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .unwrap();
        assert!(!packet.peer_manager_header().unwrap().is_compressed());

        compressor.decompress(&mut packet).unwrap();
        assert_eq!(packet.payload(), text);
        assert!(!packet.peer_manager_header().unwrap().is_compressed());
    }
}
