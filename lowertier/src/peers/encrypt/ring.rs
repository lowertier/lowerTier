use rand::RngCore;
use ring::aead::{self};
use ring::aead::{LessSafeKey, UnboundKey};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::tunnel::packet_def::{StandardAeadTail, ZCPacket};

use super::{Encryptor, Error};

#[derive(Clone)]
pub struct RingCipher {
    pub(crate) cipher: RingEnum,
}

pub enum RingEnum {
    Aes128Gcm(LessSafeKey, [u8; 16]),
    Aes256Gcm(LessSafeKey, [u8; 32]),
    ChaCha20Poly1305(LessSafeKey, [u8; 32]),
}

impl RingEnum {
    fn get_cipher(&self) -> &LessSafeKey {
        match &self {
            RingEnum::Aes128Gcm(cipher, _) => cipher,
            RingEnum::Aes256Gcm(cipher, _) => cipher,
            RingEnum::ChaCha20Poly1305(cipher, _) => cipher,
        }
    }
}

impl Clone for RingEnum {
    fn clone(&self) -> Self {
        match &self {
            RingEnum::Aes128Gcm(_, key) => {
                let c =
                    LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key.as_slice()).unwrap());
                RingEnum::Aes128Gcm(c, *key)
            }
            RingEnum::Aes256Gcm(_, key) => {
                let c =
                    LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key.as_slice()).unwrap());
                RingEnum::Aes256Gcm(c, *key)
            }
            RingEnum::ChaCha20Poly1305(_, key) => {
                let c = LessSafeKey::new(
                    UnboundKey::new(&aead::CHACHA20_POLY1305, key.as_slice()).unwrap(),
                );
                RingEnum::ChaCha20Poly1305(c, *key)
            }
        }
    }
}

impl RingCipher {
    pub fn new_aes128_gcm(key: [u8; 16]) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
        Self {
            cipher: RingEnum::Aes128Gcm(cipher, key),
        }
    }

    pub fn new_aes256_gcm(key: [u8; 32]) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
        Self {
            cipher: RingEnum::Aes256Gcm(cipher, key),
        }
    }

    pub fn new_chacha20_poly1305(key: [u8; 32]) -> Self {
        let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
        let cipher = LessSafeKey::new(unbound_key);
        Self {
            cipher: RingEnum::ChaCha20Poly1305(cipher, key),
        }
    }
}

impl Encryptor for RingCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        self.decrypt_with_aad(zc_packet, &[])
    }

    fn decrypt_with_aad(&self, zc_packet: &mut ZCPacket, aad: &[u8]) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if !pm_header.is_encrypted() {
            // A secure decrypt call must never turn plaintext into success.
            return Err(Error::DecryptionFailed);
        }

        let payload_len = zc_packet.payload().len();
        if payload_len < StandardAeadTail::SIZE {
            return Err(Error::PacketTooShort(zc_packet.payload().len()));
        }

        let text_and_tag_len = payload_len - StandardAeadTail::SIZE + StandardAeadTail::TAG_SIZE;

        let aes_tail = StandardAeadTail::ref_from_suffix(zc_packet.payload()).unwrap();
        let nonce = aead::Nonce::assume_unique_for_key(aes_tail.nonce);

        self.cipher
            .get_cipher()
            .open_in_place(
                nonce,
                aead::Aad::from(aad),
                &mut zc_packet.mut_payload_preserving_flow_hash()[..text_and_tag_len],
            )
            .map_err(|_| Error::DecryptionFailed)?;

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

        let mut tail = StandardAeadTail::new_zeroed();

        match nonce {
            Some(n) => tail.nonce = n.try_into().map_err(|_| Error::EncryptionFailed)?,
            None => rand::thread_rng().fill_bytes(&mut tail.nonce),
        }
        let nonce = aead::Nonce::assume_unique_for_key(tail.nonce);

        let tag = self
            .cipher
            .get_cipher()
            .seal_in_place_separate_tag(
                nonce,
                aead::Aad::from(aad),
                zc_packet.mut_payload_preserving_flow_hash(),
            )
            .map_err(|_| Error::EncryptionFailed)?;

        let tag = tag.as_ref();
        if tag.len() != StandardAeadTail::TAG_SIZE {
            return Err(Error::InvalidTag(tag.to_vec()));
        }
        tail.tag.copy_from_slice(tag);

        let pm_header = zc_packet.mut_peer_manager_header().unwrap();
        pm_header.set_encrypted(true);
        zc_packet
            .mut_inner_preserving_flow_hash()
            .extend_from_slice(tail.as_bytes());
        Ok(())
    }
}
