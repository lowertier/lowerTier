use aes_gcm::{AeadCore, AeadInPlace, Aes128Gcm, Aes256Gcm, Key, KeyInit};
use rand::rngs::OsRng;
use zerocopy::{AsBytes, FromBytes};

use crate::tunnel::packet_def::{StandardAeadTail, ZCPacket};

use super::{Encryptor, Error};

#[derive(Clone)]
pub struct AesGcmCipher {
    pub(crate) cipher: AesGcmEnum,
}

#[derive(Clone)]
pub enum AesGcmEnum {
    AES128GCM(Box<Aes128Gcm>),
    AES256GCM(Box<Aes256Gcm>),
}

impl AesGcmCipher {
    pub fn new_128(key: [u8; 16]) -> Self {
        let key: &Key<Aes128Gcm> = &key.into();
        Self {
            cipher: AesGcmEnum::AES128GCM(Box::new(Aes128Gcm::new(key))),
        }
    }
    pub fn new_256(key: [u8; 32]) -> Self {
        let key: &Key<Aes256Gcm> = &key.into();
        Self {
            cipher: AesGcmEnum::AES256GCM(Box::new(Aes256Gcm::new(key))),
        }
    }
}

impl Encryptor for AesGcmCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        self.decrypt_with_aad(zc_packet, &[])
    }

    fn decrypt_with_aad(&self, zc_packet: &mut ZCPacket, aad: &[u8]) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_encrypted() {
            return Ok(());
        }

        let payload_len = zc_packet.payload().len();
        if payload_len < StandardAeadTail::SIZE {
            return Err(Error::PacketTooShort(zc_packet.payload().len()));
        }

        let text_len = payload_len - StandardAeadTail::SIZE;

        let aes_tail = StandardAeadTail::ref_from_suffix(zc_packet.payload())
            .unwrap()
            .clone();

        let nonce = aes_tail.nonce.into();
        let tag = aes_tail.tag.into();

        let rs = match &self.cipher {
            AesGcmEnum::AES128GCM(aes_gcm) => aes_gcm.decrypt_in_place_detached(
                &nonce,
                aad,
                &mut zc_packet.mut_payload_preserving_flow_hash()[..text_len],
                &tag,
            ),
            AesGcmEnum::AES256GCM(aes_gcm) => aes_gcm.decrypt_in_place_detached(
                &nonce,
                aad,
                &mut zc_packet.mut_payload_preserving_flow_hash()[..text_len],
                &tag,
            ),
        };

        if let Err(e) = rs {
            println!("error: {:?}", e.to_string());
            return Err(Error::DecryptionFailed);
        }

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(false);
        let old_len = zc_packet.buf_len();
        zc_packet
            .mut_inner_preserving_flow_hash()
            .truncate(old_len - StandardAeadTail::SIZE);
        Ok(())
    }

    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        self.encrypt_with_nonce_and_aad(zc_packet, None, &[])
    }

    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        nonce: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.encrypt_with_nonce_and_aad(zc_packet, nonce, &[])
    }

    fn encrypt_with_nonce_and_aad(
        &self,
        zc_packet: &mut ZCPacket,
        nonce: Option<&[u8]>,
        aad: &[u8],
    ) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            tracing::warn!(?zc_packet, "packet is already encrypted");
            return Ok(());
        }

        let nonce = nonce
            .map(|n| {
                <[u8; StandardAeadTail::NONCE_SIZE]>::try_from(n)
                    .map(Into::into)
                    .map_err(|_| Error::EncryptionFailed)
            })
            .transpose()?;

        let (tag, nonce) = match &self.cipher {
            AesGcmEnum::AES128GCM(aes_gcm) => {
                let nonce = nonce.unwrap_or_else(|| Aes128Gcm::generate_nonce(&mut OsRng));
                (
                    aes_gcm.encrypt_in_place_detached(
                        &nonce,
                        aad,
                        zc_packet.mut_payload_preserving_flow_hash(),
                    ),
                    nonce,
                )
            }
            AesGcmEnum::AES256GCM(aes_gcm) => {
                let nonce = nonce.unwrap_or_else(|| Aes256Gcm::generate_nonce(&mut OsRng));
                (
                    aes_gcm.encrypt_in_place_detached(
                        &nonce,
                        aad,
                        zc_packet.mut_payload_preserving_flow_hash(),
                    ),
                    nonce,
                )
            }
        };

        let tail = StandardAeadTail {
            tag: tag.map_err(|_| Error::EncryptionFailed)?.into(),
            nonce: nonce.into(),
        };

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(true);
        zc_packet
            .mut_inner_preserving_flow_hash()
            .extend_from_slice(tail.as_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peers::encrypt::{Encryptor, aes_gcm::AesGcmCipher},
        tunnel::packet_def::{StandardAeadTail, ZCPacket},
    };
    use zerocopy::FromBytes;
}
