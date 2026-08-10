use crate::{
    common::{config::EncryptionAlgorithm, log},
    tunnel::packet_def::ZCPacket,
};
use std::sync::Arc;

pub mod ring;

#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;

#[cfg(feature = "openssl-crypto")]
pub mod openssl;

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
    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        _nonce: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.encrypt(zc_packet)
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
    #[allow(unused_variables)] key_256: [u8; 32],
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

    match algorithm {
        EncryptionAlgorithm::AesGcm => {
            #[cfg(feature = "openssl-crypto")]
            {
                Arc::new(openssl::OpenSslCipher::new_aes128_gcm(key_128))
            }
            #[cfg(all(not(feature = "openssl-crypto"), feature = "aes-gcm"))]
            {
                Arc::new(aes_gcm::AesGcmCipher::new_128(key_128))
            }
            #[cfg(not(any(feature = "openssl-crypto", feature = "aes-gcm")))]
            {
                Arc::new(ring::RingCipher::new_aes128_gcm(key_128))
            }
        }

        EncryptionAlgorithm::Aes256Gcm => {
            #[cfg(feature = "openssl-crypto")]
            {
                Arc::new(openssl::OpenSslCipher::new_aes256_gcm(key_256))
            }
            #[cfg(all(not(feature = "openssl-crypto"), feature = "aes-gcm"))]
            {
                Arc::new(aes_gcm::AesGcmCipher::new_256(key_256))
            }
            #[cfg(not(any(feature = "openssl-crypto", feature = "aes-gcm")))]
            {
                Arc::new(ring::RingCipher::new_aes256_gcm(key_256))
            }
        }

        EncryptionAlgorithm::ChaCha20Poly1305 => {
            #[cfg(feature = "openssl-crypto")]
            {
                Arc::new(openssl::OpenSslCipher::new_chacha20_poly1305(key_256))
            }
            #[cfg(not(feature = "openssl-crypto"))]
            {
                Arc::new(ring::RingCipher::new_chacha20_poly1305(key_256))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::create_encryptor;
    use crate::tunnel::packet_def::{StandardAeadTail, ZCPacket};

    #[test]
    fn standard_chacha20_poly1305_factory_round_trip() {
        let plaintext = b"authenticated easytier payload";
        let cipher = create_encryptor("chacha20-poly1305", [3; 16], [7; 32]);
        let mut packet = ZCPacket::new_with_payload(plaintext);
        packet.fill_peer_manager_hdr(1, 2, 3);

        cipher.encrypt(&mut packet).unwrap();
        assert!(packet.peer_manager_header().unwrap().is_encrypted());
        assert_eq!(
            packet.payload().len(),
            plaintext.len() + StandardAeadTail::SIZE
        );
        assert_ne!(&packet.payload()[..plaintext.len()], plaintext);

        cipher.decrypt(&mut packet).unwrap();
        assert_eq!(packet.payload(), plaintext);
    }

    #[test]
    fn standard_chacha20_poly1305_rejects_tampering() {
        let cipher = create_encryptor("chacha20-poly1305", [3; 16], [7; 32]);
        let mut packet = ZCPacket::new_with_payload(b"authenticated easytier payload");
        packet.fill_peer_manager_hdr(1, 2, 3);
        cipher.encrypt(&mut packet).unwrap();

        packet.mut_payload()[0] ^= 1;

        assert!(cipher.decrypt(&mut packet).is_err());
    }
}
