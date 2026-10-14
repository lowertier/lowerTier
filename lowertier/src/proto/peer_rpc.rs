use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;

use crate::common::PeerId;

include!(concat!(env!("OUT_DIR"), "/peer_rpc.rs"));
include!(concat!(env!("OUT_DIR"), "/peer_rpc.serde.rs"));

impl PeerGroupInfo {
    pub fn generate_with_proof(group_name: String, group_secret: String, peer_id: PeerId) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(group_secret.as_bytes())
            .expect("HMAC can take key of any size");

        let mut data_to_sign = group_name.as_bytes().to_vec();
        data_to_sign.push(0x00); // Add a delimiter byte
        data_to_sign.extend_from_slice(&peer_id.to_be_bytes());

        mac.update(&data_to_sign);

        let proof = mac.finalize().into_bytes().to_vec();

        PeerGroupInfo {
            group_name,
            group_proof: proof,
        }
    }

    pub fn verify(&self, group_secret: &str, peer_id: PeerId) -> bool {
        let mut verifier = Hmac::<Sha256>::new_from_slice(group_secret.as_bytes())
            .expect("HMAC can take key of any size");

        let mut data_to_sign = self.group_name.as_bytes().to_vec();
        data_to_sign.push(0x00); // Add a delimiter byte
        data_to_sign.extend_from_slice(&peer_id.to_be_bytes());

        verifier.update(&data_to_sign);

        verifier.verify_slice(&self.group_proof).is_ok()
    }
}

impl TrustedCredentialPubkeyProof {
    pub fn generate_credential_hmac_from_bytes(
        credential_bytes: &[u8],
        network_secret: &str,
    ) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(network_secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(b"lowertier credential proof");
        mac.update(credential_bytes);
        mac.finalize().into_bytes().to_vec()
    }

    pub fn generate_credential_hmac(
        credential: &TrustedCredentialPubkey,
        network_secret: &str,
    ) -> Vec<u8> {
        Self::generate_credential_hmac_from_bytes(&credential.encode_to_vec(), network_secret)
    }

    pub fn new_signed(credential: TrustedCredentialPubkey, network_secret: &str) -> Self {
        let credential_hmac = Self::generate_credential_hmac(&credential, network_secret);
        Self {
            credential: Some(credential),
            credential_hmac,
        }
    }

    pub fn verify_credential_hmac(&self, network_secret: &str) -> bool {
        let Some(credential) = self.credential.as_ref() else {
            return false;
        };
        self.verify_credential_hmac_with_bytes(&credential.encode_to_vec(), network_secret)
    }

    pub fn verify_credential_hmac_with_bytes(
        &self,
        credential_bytes: &[u8],
        network_secret: &str,
    ) -> bool {
        if self.credential_hmac.is_empty() {
            return false;
        }

        let mut mac = Hmac::<Sha256>::new_from_slice(network_secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(b"lowertier credential proof");
        mac.update(credential_bytes);
        mac.verify_slice(&self.credential_hmac).is_ok()
    }
}

impl From<RouteConnBitmap> for sync_route_info_request::ConnInfo {
    fn from(val: RouteConnBitmap) -> Self {
        Self::ConnBitmap(val)
    }
}

impl From<RouteConnPeerList> for sync_route_info_request::ConnInfo {
    fn from(val: RouteConnPeerList) -> Self {
        Self::ConnPeerList(val)
    }
}
