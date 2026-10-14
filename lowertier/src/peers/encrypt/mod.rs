use crate::{
    common::{config::EncryptionAlgorithm, log},
    tunnel::packet_def::ZCPacket,
};
use std::sync::Arc;

pub mod ring;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("packet is too short. len: {0}")]
    PacketTooShort(usize),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("invalid tag. tag: {0:?}")]
    InvalidTag(Vec<u8>),
}

pub trait Encryptor: Send + Sync + 'static {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn decrypt_with_aad(&self, zc_packet: &mut ZCPacket, _aad: &[u8]) -> Result<(), Error> {
        self.decrypt(zc_packet)
    }
    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        _nonce: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.encrypt(zc_packet)
    }
    fn encrypt_with_nonce_and_aad(
        &self,
        zc_packet: &mut ZCPacket,
        nonce: Option<&[u8]>,
        _aad: &[u8],
    ) -> Result<(), Error> {
        self.encrypt_with_nonce(zc_packet, nonce)
    }
}

pub struct NullCipher;

impl Encryptor for NullCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            Err(Error::DecryptionFailed)
        } else {
            Ok(())
        }
    }

    fn encrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Ok(())
    }
}

/// Create an encryptor based on the algorithm name
pub fn create_encryptor(
    algorithm: &str,
    key_128: [u8; 16],
    key_256: [u8; 32],
) -> Arc<dyn Encryptor> {
    let algorithm = match EncryptionAlgorithm::try_from(algorithm) {
        Ok(algorithm) => algorithm,
        Err(_) => {
            let default = EncryptionAlgorithm::default();
            log::warn!(
                "Unknown encryption algorithm: {}, falling back to default {}",
                algorithm,
                default
            );
            default
        }
    };

    create_ring_encryptor(algorithm, key_128, key_256)
}

fn create_ring_encryptor(
    algorithm: EncryptionAlgorithm,
    key_128: [u8; 16],
    key_256: [u8; 32],
) -> Arc<dyn Encryptor> {
    match algorithm {
        EncryptionAlgorithm::AesGcm => Arc::new(ring::RingCipher::new_aes128_gcm(key_128)),
        EncryptionAlgorithm::Aes256Gcm => Arc::new(ring::RingCipher::new_aes256_gcm(key_256)),
        EncryptionAlgorithm::ChaCha20Poly1305 => {
            Arc::new(ring::RingCipher::new_chacha20_poly1305(key_256))
        }
    }
}

/// Create the in-place backend used by secure datagram sessions.
///
/// The ring backend supports every negotiated algorithm and preserves the packet tail.
pub fn create_secure_datagram_encryptor(
    algorithm: &str,
    key_128: [u8; 16],
    key_256: [u8; 32],
) -> Arc<dyn Encryptor> {
    create_ring_encryptor(
        EncryptionAlgorithm::try_from(algorithm).unwrap_or_default(),
        key_128,
        key_256,
    )
}
