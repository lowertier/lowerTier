use std::{
    collections::{BTreeSet, HashMap},
    io::Write,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
};
use prost::Message;
use rand::RngCore;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::proto::{
    api::instance::CredentialInfo,
    peer_rpc::{
        CredentialBundle, CredentialCertificate, CredentialCertificateStatus,
        CredentialRevocationState, TrustedCredentialPubkey, TrustedCredentialPubkeyProof,
    },
};

const CREDENTIAL_BUNDLE_VERSION: u32 = 1;
const CREDENTIAL_STATE_VERSION: u32 = 1;
const ROOT_SEED_DOMAIN: &[u8] = b"lowertier credential root seed v1";
const ROOT_FINGERPRINT_DOMAIN: &[u8] = b"lowertier credential root fingerprint v1";
const CERTIFICATE_DOMAIN: &[u8] = b"lowertier credential certificate v1";
const REVOCATION_DOMAIN: &[u8] = b"lowertier credential revocation v1";
const CERTIFICATE_ID_LEN: usize = 16;
const MAX_CREDENTIAL_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_REVOCATION_AGE: i64 = 24 * 60 * 60;
const MAX_FUTURE_SKEW: i64 = 5 * 60;
const MAX_STATUS_LIFETIME: Duration = Duration::from_secs(60);
const STATUS_DOMAIN: &[u8] = b"lowertier credential certificate status v1";

fn default_true() -> bool {
    true
}

pub fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialEntry {
    pubkey: String,
    #[serde(default)]
    bundle: String,
    #[serde(default)]
    certificate_id: Vec<u8>,
    #[serde(default)]
    role: String,
    #[serde(default)]
    certificate_signature: Vec<u8>,
    #[serde(default)]
    certificate_bytes: Vec<u8>,
    groups: Vec<String>,
    allow_relay: bool,
    allowed_proxy_cidrs: Vec<String>,
    #[serde(default = "default_true")]
    reusable: bool,
    expiry_unix: i64,
    created_at_unix: i64,
}

impl CredentialEntry {
    fn is_active_at(&self, now: i64, revoked: &BTreeSet<Vec<u8>>) -> bool {
        self.certificate_id.len() == CERTIFICATE_ID_LEN
            && self.expiry_unix > now
            && !revoked.contains(&self.certificate_id)
    }

    fn to_trusted_credential(
        &self,
        network_name: &str,
        root_public_key: &[u8],
        root_fingerprint: &[u8],
    ) -> Option<TrustedCredentialPubkey> {
        Some(TrustedCredentialPubkey {
            pubkey: CredentialManager::decode_pubkey_b64(&self.pubkey)?,
            groups: self.groups.clone(),
            allow_relay: self.allow_relay,
            expiry_unix: self.expiry_unix,
            allowed_proxy_cidrs: self.allowed_proxy_cidrs.clone(),
            reusable: Some(self.reusable),
            credential_version: CREDENTIAL_BUNDLE_VERSION,
            serial: 0,
            network_name: network_name.to_owned(),
            root_public_key: root_public_key.to_vec(),
            root_fingerprint: root_fingerprint.to_vec(),
            role: self.role.clone(),
            certificate_signature: self.certificate_signature.clone(),
            certificate: CredentialCertificate::decode(self.certificate_bytes.as_slice()).ok(),
            certificate_id: self.certificate_id.clone(),
        })
    }

    fn to_api_credential_info(
        &self,
        credential_id: &str,
        network_name: &str,
        root_fingerprint: &[u8],
    ) -> CredentialInfo {
        CredentialInfo {
            credential_id: credential_id.to_owned(),
            groups: self.groups.clone(),
            allow_relay: self.allow_relay,
            expiry_unix: self.expiry_unix,
            allowed_proxy_cidrs: self.allowed_proxy_cidrs.clone(),
            reusable: Some(self.reusable),
            credential_version: CREDENTIAL_BUNDLE_VERSION,
            serial: 0,
            role: self.role.clone(),
            network_name: network_name.to_owned(),
            root_fingerprint: root_fingerprint.to_vec(),
            certificate_id: self.certificate_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CredentialStore {
    credentials: HashMap<String, CredentialEntry>,
    #[serde(default)]
    revocation_state_version: u64,
    #[serde(default)]
    revoked_certificate_ids: BTreeSet<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    InvalidEncoding,
    InvalidBundle,
    WrongNetwork,
    WrongRoot,
    Expired,
    Revoked,
    InvalidSignature,
    InvalidSerial,
    InvalidStateVersion,
    InvalidCertificateId,
    InvalidLifetime,
    IssuerUnavailable,
    FutureTimestamp,
    DuplicatePolicyValue,
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CredentialError {}

pub struct CredentialManager {
    credentials: Mutex<CredentialStore>,
    storage_path: Option<PathBuf>,
    network_name: String,
    root_seed: Option<[u8; 32]>,
    root_public_key: [u8; 32],
    root_fingerprint: [u8; 32],
}

impl CredentialManager {
    /// Build an administrator manager with deterministic root material for a network.
    pub fn new_with_network(
        storage_path: Option<PathBuf>,
        network_name: impl Into<String>,
        network_secret: Option<&str>,
    ) -> Self {
        Self::try_new_with_network_and_bundle(
            storage_path,
            network_name,
            network_secret.filter(|secret| !secret.is_empty()),
            None,
            None,
        )
        .expect("administrator credential manager requires network identity")
    }

    /// Build a manager and reject credential nodes without a verified bundle.
    pub fn new_with_network_and_bundle(
        storage_path: Option<PathBuf>,
        network_name: impl Into<String>,
        network_secret: Option<&str>,
        credential_bundle: Option<&str>,
    ) -> Result<Self, CredentialError> {
        Self::try_new_with_network_and_bundle(
            storage_path,
            network_name,
            network_secret,
            credential_bundle,
            None,
        )
    }

    /// Build a manager and verify a credential bundle against a pinned root.
    pub fn new_with_network_and_bundle_pinned(
        storage_path: Option<PathBuf>,
        network_name: impl Into<String>,
        network_secret: Option<&str>,
        credential_bundle: Option<&str>,
        pinned_root_fingerprint: Option<&[u8]>,
    ) -> Result<Self, CredentialError> {
        Self::try_new_with_network_and_bundle(
            storage_path,
            network_name,
            network_secret,
            credential_bundle,
            pinned_root_fingerprint,
        )
    }

    fn try_new_with_network_and_bundle(
        storage_path: Option<PathBuf>,
        network_name: impl Into<String>,
        network_secret: Option<&str>,
        credential_bundle: Option<&str>,
        pinned_root_fingerprint: Option<&[u8]>,
    ) -> Result<Self, CredentialError> {
        let network_name = network_name.into();
        let network_secret = network_secret.filter(|secret| !secret.is_empty());
        let (root_seed, root_public_key, root_fingerprint) =
            if let Some(network_secret) = network_secret {
                let root_seed = derive_root_seed(&network_name, network_secret);
                let root_key = Ed25519KeyPair::from_seed_unchecked(&root_seed)
                    .expect("a SHA-256 seed is a valid Ed25519 seed");
                let mut root_public_key = [0_u8; 32];
                root_public_key.copy_from_slice(root_key.public_key().as_ref());
                let mut root_fingerprint = [0_u8; 32];
                root_fingerprint.copy_from_slice(&root_fingerprint_for(&root_public_key));
                (Some(root_seed), root_public_key, root_fingerprint)
            } else {
                if let Some(encoded) = credential_bundle {
                    let bundle = Self::verify_credential_bundle_for_network(
                        encoded,
                        &network_name,
                        pinned_root_fingerprint,
                        current_unix_timestamp(),
                    )?;
                    let root_public_key: [u8; 32] = bundle
                        .root_public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| CredentialError::WrongRoot)?;
                    let root_fingerprint: [u8; 32] = bundle
                        .root_fingerprint
                        .as_slice()
                        .try_into()
                        .map_err(|_| CredentialError::WrongRoot)?;
                    (None, root_public_key, root_fingerprint)
                } else {
                    // Shared nodes do not issue or trust credentials.
                    (None, [0_u8; 32], root_fingerprint_for(&[0_u8; 32]))
                }
            };
        let manager = Self {
            credentials: Mutex::new(CredentialStore::default()),
            storage_path,
            network_name,
            root_seed,
            root_public_key,
            root_fingerprint,
        };
        manager.load_from_disk();
        Ok(manager)
    }

    pub fn network_name(&self) -> &str {
        &self.network_name
    }

    pub fn root_public_key(&self) -> &[u8; 32] {
        &self.root_public_key
    }

    pub fn root_fingerprint(&self) -> &[u8; 32] {
        &self.root_fingerprint
    }

    pub fn generate_credential(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
    ) -> Result<(String, String), CredentialError> {
        self.generate_credential_with_options(
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            ttl,
            None,
            true,
        )
    }

    pub fn generate_credential_with_id(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
        credential_id: Option<String>,
    ) -> Result<(String, String), CredentialError> {
        self.generate_credential_with_options(
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            ttl,
            credential_id,
            true,
        )
    }

    /// Generate a signed bundle for the credential RPC.
    pub fn generate_credential_bundle(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
        credential_id: Option<String>,
        reusable: bool,
    ) -> Result<(String, String), CredentialError> {
        if self.root_seed.is_none() {
            return Err(CredentialError::IssuerUnavailable);
        }
        if ttl.as_secs() == 0 || ttl > MAX_CREDENTIAL_TTL {
            return Err(CredentialError::InvalidLifetime);
        }
        self.remove_expired_credentials();
        let mut store = self.credentials.lock().unwrap();
        let id = credential_id
            .and_then(|id| (!id.trim().is_empty()).then_some(id.trim().to_owned()))
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        if let Some(existing) = store.credentials.get(&id)
            && !existing.bundle.is_empty()
        {
            return Ok((id, existing.bundle.clone()));
        }
        let certificate_id = loop {
            let mut certificate_id = vec![0_u8; CERTIFICATE_ID_LEN];
            rand::rngs::OsRng.fill_bytes(&mut certificate_id);
            if certificate_id.iter().any(|byte| *byte != 0)
                && !store
                    .credentials
                    .values()
                    .any(|entry| entry.certificate_id == certificate_id)
            {
                break certificate_id;
            }
        };
        let now = current_unix_timestamp();
        let expiry = now.saturating_add(ttl.as_secs().try_into().unwrap_or(i64::MAX));
        let private = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&private);
        let groups = canonical_strings_checked(groups)?;
        let allowed_proxy_cidrs = canonical_strings_checked(allowed_proxy_cidrs)?;
        let certificate = self.sign_certificate(
            public.as_bytes(),
            &certificate_id,
            now,
            expiry,
            "Credential",
            &groups,
            allow_relay,
            &allowed_proxy_cidrs,
            reusable,
        )?;
        let bundle = CredentialBundle {
            version: CREDENTIAL_BUNDLE_VERSION,
            x25519_private_key: private.to_bytes().to_vec(),
            network_name: self.network_name.clone(),
            root_public_key: self.root_public_key.to_vec(),
            root_fingerprint: self.root_fingerprint.to_vec(),
            serial: 0,
            certificate: Some(certificate.clone()),
            issued_unix: now,
            expiry_unix: expiry,
            role: "Credential".to_owned(),
            groups: groups.clone(),
            allow_relay,
            allowed_proxy_cidrs: allowed_proxy_cidrs.clone(),
            reusable,
            certificate_id: certificate_id.clone(),
        };
        let encoded = encode_bundle(&bundle);
        store.credentials.insert(
            id.clone(),
            CredentialEntry {
                pubkey: BASE64_STANDARD.encode(public.as_bytes()),
                bundle: encoded.clone(),
                certificate_id,
                role: "Credential".to_owned(),
                certificate_signature: certificate.signature.clone(),
                certificate_bytes: certificate.encode_to_vec(),
                groups,
                allow_relay,
                allowed_proxy_cidrs,
                reusable,
                expiry_unix: expiry,
                created_at_unix: now,
            },
        );
        drop(store);
        self.save_to_disk();
        Ok((id, encoded))
    }

    /// Generate only a signed bundle. Raw private-key output is not supported.
    pub fn generate_credential_with_options(
        &self,
        groups: Vec<String>,
        allow_relay: bool,
        allowed_proxy_cidrs: Vec<String>,
        ttl: Duration,
        credential_id: Option<String>,
        reusable: bool,
    ) -> Result<(String, String), CredentialError> {
        self.generate_credential_bundle(
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            ttl,
            credential_id,
            reusable,
        )
    }

    pub fn new_admin_certificate(
        &self,
        x25519_public_key: &[u8; 32],
        ttl: Duration,
    ) -> Result<CredentialCertificate, CredentialError> {
        if ttl.as_secs() == 0 || ttl > MAX_CREDENTIAL_TTL {
            return Err(CredentialError::InvalidLifetime);
        }
        let now = current_unix_timestamp();
        let certificate_id = loop {
            let mut certificate_id = vec![0_u8; CERTIFICATE_ID_LEN];
            rand::rngs::OsRng.fill_bytes(&mut certificate_id);
            if certificate_id.iter().any(|byte| *byte != 0) {
                break certificate_id;
            }
        };
        self.sign_certificate(
            x25519_public_key,
            &certificate_id,
            now,
            now.saturating_add(ttl.as_secs().try_into().unwrap_or(i64::MAX)),
            "Admin",
            &[],
            true,
            &[],
            true,
        )
    }

    fn sign_certificate(
        &self,
        subject_x25519_public_key: &[u8],
        certificate_id: &[u8],
        issued_unix: i64,
        expiry_unix: i64,
        role: &str,
        groups: &[String],
        allow_relay: bool,
        allowed_proxy_cidrs: &[String],
        reusable: bool,
    ) -> Result<CredentialCertificate, CredentialError> {
        let root_seed = self
            .root_seed
            .as_ref()
            .ok_or(CredentialError::IssuerUnavailable)?;
        if certificate_id.len() != CERTIFICATE_ID_LEN {
            return Err(CredentialError::InvalidCertificateId);
        }
        let groups = groups.to_vec();
        let allowed_proxy_cidrs = allowed_proxy_cidrs.to_vec();
        let mut certificate = CredentialCertificate {
            version: CREDENTIAL_BUNDLE_VERSION,
            network_name: self.network_name.clone(),
            root_public_key: self.root_public_key.to_vec(),
            root_fingerprint: self.root_fingerprint.to_vec(),
            subject_x25519_public_key: subject_x25519_public_key.to_vec(),
            serial: 0,
            certificate_id: certificate_id.to_vec(),
            issued_unix,
            expiry_unix,
            role: role.to_owned(),
            groups,
            allow_relay,
            allowed_proxy_cidrs,
            reusable,
            signature: Vec::new(),
        };
        let key_pair = Ed25519KeyPair::from_seed_unchecked(root_seed)
            .expect("the stored root seed remains valid");
        let signature = key_pair.sign(&certificate_signing_bytes(&certificate));
        certificate.signature = signature.as_ref().to_vec();
        Ok(certificate)
    }

    pub fn try_revoke_credential(&self, credential_id: &str) -> Result<bool, CredentialError> {
        if self.root_seed.is_none() {
            return Err(CredentialError::IssuerUnavailable);
        }
        let mut store = self.credentials.lock().unwrap();
        let Some(entry) = store.credentials.get(credential_id).cloned() else {
            return Ok(false);
        };
        if entry.certificate_id.len() != CERTIFICATE_ID_LEN {
            return Err(CredentialError::InvalidCertificateId);
        }
        let next_version = store
            .revocation_state_version
            .checked_add(1)
            .ok_or(CredentialError::InvalidStateVersion)?;
        store.credentials.remove(credential_id);
        store.revoked_certificate_ids.insert(entry.certificate_id);
        store.revocation_state_version = next_version;
        drop(store);
        self.save_to_disk();
        Ok(true)
    }

    pub fn remove_expired_credentials(&self) -> bool {
        self.remove_expired_credentials_at(current_unix_timestamp())
    }

    fn remove_expired_credentials_at(&self, now: i64) -> bool {
        let mut store = self.credentials.lock().unwrap();
        let before = store.credentials.len();
        let revoked_certificate_ids = store.revoked_certificate_ids.clone();
        store
            .credentials
            .retain(|_, entry| entry.is_active_at(now, &revoked_certificate_ids));
        let removed = before != store.credentials.len();
        drop(store);
        if removed {
            self.save_to_disk();
        }
        removed
    }

    pub fn get_trusted_pubkeys(&self, network_secret: &str) -> Vec<TrustedCredentialPubkeyProof> {
        if self.root_seed.is_none() {
            return Vec::new();
        }
        let now = current_unix_timestamp();
        let store = self.credentials.lock().unwrap();
        store
            .credentials
            .values()
            .filter(|entry| entry.is_active_at(now, &store.revoked_certificate_ids))
            .filter_map(|entry| {
                entry
                    .to_trusted_credential(
                        &self.network_name,
                        &self.root_public_key,
                        &self.root_fingerprint,
                    )
                    .map(|credential| {
                        TrustedCredentialPubkeyProof::new_signed(credential, network_secret)
                    })
            })
            .collect()
    }

    pub fn is_pubkey_trusted(&self, pubkey: &[u8]) -> bool {
        let now = current_unix_timestamp();
        let encoded = BASE64_STANDARD.encode(pubkey);
        let store = self.credentials.lock().unwrap();
        store.credentials.values().any(|entry| {
            entry.pubkey == encoded && entry.is_active_at(now, &store.revoked_certificate_ids)
        })
    }

    pub fn list_credentials(&self) -> Vec<CredentialInfo> {
        let now = current_unix_timestamp();
        let store = self.credentials.lock().unwrap();
        store
            .credentials
            .iter()
            .filter(|(_, entry)| entry.is_active_at(now, &store.revoked_certificate_ids))
            .map(|(id, entry)| {
                entry.to_api_credential_info(id, &self.network_name, &self.root_fingerprint)
            })
            .collect()
    }

    pub fn revocation_state(&self) -> Result<String, CredentialError> {
        let root_seed = self
            .root_seed
            .as_ref()
            .ok_or(CredentialError::IssuerUnavailable)?;
        let store = self.credentials.lock().unwrap();
        let mut state = CredentialRevocationState {
            version: CREDENTIAL_STATE_VERSION,
            network_name: self.network_name.clone(),
            root_public_key: self.root_public_key.to_vec(),
            root_fingerprint: self.root_fingerprint.to_vec(),
            state_version: store.revocation_state_version,
            revoked_serials: Vec::new(),
            issued_unix: current_unix_timestamp(),
            signature: Vec::new(),
            revoked_certificate_ids: store.revoked_certificate_ids.iter().cloned().collect(),
        };
        let key_pair = Ed25519KeyPair::from_seed_unchecked(root_seed)
            .expect("the stored root seed remains valid");
        state.signature = key_pair
            .sign(&revocation_signing_bytes(&state))
            .as_ref()
            .to_vec();
        Ok(URL_SAFE_NO_PAD.encode(state.encode_to_vec()))
    }

    /// Create a short-lived signed status assertion for one certificate.
    pub fn new_admin_certificate_status(
        &self,
        certificate_id: &[u8],
        ttl: Duration,
    ) -> Result<CredentialCertificateStatus, CredentialError> {
        self.new_admin_certificate_status_ephemeral(certificate_id, ttl)
    }

    /// Create status evidence without changing persistent issuer state.
    pub fn new_admin_certificate_status_ephemeral(
        &self,
        certificate_id: &[u8],
        ttl: Duration,
    ) -> Result<CredentialCertificateStatus, CredentialError> {
        let root_seed = self
            .root_seed
            .as_ref()
            .ok_or(CredentialError::IssuerUnavailable)?;
        if certificate_id.len() != CERTIFICATE_ID_LEN
            || certificate_id.iter().all(|byte| *byte == 0)
        {
            return Err(CredentialError::InvalidCertificateId);
        }
        if ttl.as_secs() == 0 || ttl > MAX_STATUS_LIFETIME {
            return Err(CredentialError::InvalidLifetime);
        }
        let now = current_unix_timestamp();
        let sequence = current_unix_millis();
        let revoked = self
            .credentials
            .lock()
            .unwrap()
            .revoked_certificate_ids
            .contains(certificate_id);
        let mut status = CredentialCertificateStatus {
            version: CREDENTIAL_STATE_VERSION,
            network_name: self.network_name.clone(),
            root_fingerprint: self.root_fingerprint.to_vec(),
            certificate_id: certificate_id.to_vec(),
            sequence,
            issued_unix: now,
            not_after_unix: now.saturating_add(ttl.as_secs() as i64),
            revoked,
            signature: Vec::new(),
            root_public_key: self.root_public_key.to_vec(),
        };
        let key_pair = Ed25519KeyPair::from_seed_unchecked(root_seed)
            .expect("the stored root seed remains valid");
        status.signature = key_pair
            .sign(&status_signing_bytes(&status))
            .as_ref()
            .to_vec();
        Ok(status)
    }

    /// Encode a short-lived signed status assertion for transport.
    pub fn new_admin_certificate_status_bytes(
        &self,
        certificate_id: &[u8],
        ttl: Duration,
    ) -> Result<Vec<u8>, CredentialError> {
        Ok(self
            .new_admin_certificate_status(certificate_id, ttl)?
            .encode_to_vec())
    }

    pub fn parse_credential_bundle(encoded: &str) -> Result<CredentialBundle, CredentialError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CredentialError::InvalidEncoding)?;
        let bundle = CredentialBundle::decode(bytes.as_slice())
            .map_err(|_| CredentialError::InvalidBundle)?;
        if bundle.encode_to_vec() != bytes {
            return Err(CredentialError::InvalidBundle);
        }
        Ok(bundle)
    }

    pub fn private_key_from_bundle(encoded: &str) -> Result<StaticSecret, CredentialError> {
        let bundle = Self::parse_credential_bundle(encoded)?;
        let private_key: [u8; 32] = bundle
            .x25519_private_key
            .as_slice()
            .try_into()
            .map_err(|_| CredentialError::InvalidBundle)?;
        Ok(StaticSecret::from(private_key))
    }

    pub fn verify_credential_bundle(
        encoded: &str,
        network_name: &str,
        root_public_key: &[u8],
        now: i64,
    ) -> Result<CredentialBundle, CredentialError> {
        let bundle = Self::parse_credential_bundle(encoded)?;
        if root_public_key.len() != 32 {
            return Err(CredentialError::WrongRoot);
        }
        if bundle.version != CREDENTIAL_BUNDLE_VERSION
            || bundle.network_name != network_name
            || bundle.root_public_key.as_slice() != root_public_key
            || bundle.root_fingerprint.as_slice()
                != root_fingerprint_for(root_public_key).as_slice()
        {
            return Err(if bundle.network_name != network_name {
                CredentialError::WrongNetwork
            } else {
                CredentialError::WrongRoot
            });
        }
        if bundle.x25519_private_key.len() != 32
            || bundle.expiry_unix <= now
            || bundle.issued_unix > now
            || bundle.expiry_unix <= bundle.issued_unix
            || bundle.expiry_unix.saturating_sub(bundle.issued_unix)
                > MAX_CREDENTIAL_TTL.as_secs() as i64
            || bundle.certificate_id.len() != CERTIFICATE_ID_LEN
            || bundle.certificate_id.iter().all(|byte| *byte == 0)
        {
            return Err(if bundle.expiry_unix <= now || bundle.issued_unix > now {
                CredentialError::Expired
            } else if bundle.expiry_unix <= bundle.issued_unix
                || bundle.expiry_unix.saturating_sub(bundle.issued_unix)
                    > MAX_CREDENTIAL_TTL.as_secs() as i64
            {
                CredentialError::InvalidLifetime
            } else {
                CredentialError::InvalidCertificateId
            });
        }
        let certificate = bundle
            .certificate
            .as_ref()
            .ok_or(CredentialError::InvalidBundle)?;
        if !is_canonical_strings(&bundle.groups)
            || !is_canonical_strings(&bundle.allowed_proxy_cidrs)
            || certificate.version != CREDENTIAL_BUNDLE_VERSION
            || certificate.serial != 0
            || certificate.certificate_id != bundle.certificate_id
            || certificate.network_name != bundle.network_name
            || certificate.root_public_key != bundle.root_public_key
            || certificate.root_fingerprint != bundle.root_fingerprint
            || certificate.subject_x25519_public_key
                != PublicKey::from(&StaticSecret::from(
                    <[u8; 32]>::try_from(bundle.x25519_private_key.as_slice())
                        .map_err(|_| CredentialError::InvalidBundle)?,
                ))
                .as_bytes()
            || certificate.expiry_unix != bundle.expiry_unix
            || certificate.issued_unix != bundle.issued_unix
            || bundle.role != "Credential"
            || certificate.role != bundle.role
            || certificate.groups != bundle.groups
            || certificate.allow_relay != bundle.allow_relay
            || certificate.allowed_proxy_cidrs != bundle.allowed_proxy_cidrs
            || certificate.reusable != bundle.reusable
            || certificate.signature.len() != 64
        {
            return Err(CredentialError::InvalidBundle);
        }
        Self::verify_credential_certificate(
            certificate,
            network_name,
            root_public_key,
            Some(bundle.root_fingerprint.as_slice()),
            now,
        )?;
        Ok(bundle)
    }

    /// Verify a certificate without requiring the private bundle key.
    pub fn verify_credential_certificate(
        certificate: &CredentialCertificate,
        network_name: &str,
        root_public_key: &[u8],
        pinned_root_fingerprint: Option<&[u8]>,
        now: i64,
    ) -> Result<(), CredentialError> {
        if root_public_key.len() != 32
            || certificate.version != CREDENTIAL_BUNDLE_VERSION
            || certificate.network_name != network_name
            || certificate.root_public_key.as_slice() != root_public_key
            || certificate.root_fingerprint.as_slice()
                != root_fingerprint_for(root_public_key).as_slice()
            || certificate.certificate_id.len() != CERTIFICATE_ID_LEN
            || certificate.certificate_id.iter().all(|byte| *byte == 0)
            || certificate.serial != 0
            || certificate.subject_x25519_public_key.len() != 32
            || certificate.expiry_unix <= now
            || certificate.issued_unix > now
            || certificate.expiry_unix <= certificate.issued_unix
            || certificate
                .expiry_unix
                .saturating_sub(certificate.issued_unix)
                > MAX_CREDENTIAL_TTL.as_secs() as i64
            || certificate.signature.len() != 64
            || !is_canonical_strings(&certificate.groups)
            || !is_canonical_strings(&certificate.allowed_proxy_cidrs)
        {
            return Err(
                if certificate.expiry_unix <= now || certificate.issued_unix > now {
                    CredentialError::Expired
                } else if certificate.expiry_unix <= certificate.issued_unix
                    || certificate
                        .expiry_unix
                        .saturating_sub(certificate.issued_unix)
                        > MAX_CREDENTIAL_TTL.as_secs() as i64
                {
                    CredentialError::InvalidLifetime
                } else {
                    CredentialError::InvalidBundle
                },
            );
        }
        if let Some(pinned) = pinned_root_fingerprint
            && pinned != certificate.root_fingerprint.as_slice()
        {
            return Err(CredentialError::WrongRoot);
        }
        UnparsedPublicKey::new(&ED25519, root_public_key)
            .verify(
                &certificate_signing_bytes(certificate),
                &certificate.signature,
            )
            .map_err(|_| CredentialError::InvalidSignature)
    }

    /// Verify the signed credential metadata carried by a peer proof.
    pub fn verify_trusted_credential(
        credential: &TrustedCredentialPubkey,
        network_name: &str,
        pinned_root_fingerprint: Option<&[u8]>,
        now: i64,
    ) -> Result<(), CredentialError> {
        if credential.pubkey.len() != 32
            || credential.root_public_key.len() != 32
            || credential.root_fingerprint.len() != 32
            || credential.certificate_id.len() != CERTIFICATE_ID_LEN
            || credential.certificate_id.iter().all(|byte| *byte == 0)
        {
            return Err(CredentialError::InvalidBundle);
        }
        let certificate = credential
            .certificate
            .as_ref()
            .ok_or(CredentialError::InvalidBundle)?;
        if certificate.certificate_id != credential.certificate_id
            || certificate.subject_x25519_public_key != credential.pubkey
            || certificate.role != "Credential"
            || certificate.groups != credential.groups
            || certificate.allow_relay != credential.allow_relay
            || certificate.expiry_unix != credential.expiry_unix
            || certificate.allowed_proxy_cidrs != credential.allowed_proxy_cidrs
            || certificate.reusable != credential.reusable.unwrap_or(false)
            || credential.certificate_signature != certificate.signature
        {
            return Err(CredentialError::InvalidBundle);
        }
        Self::verify_credential_certificate(
            certificate,
            network_name,
            &credential.root_public_key,
            pinned_root_fingerprint,
            now,
        )
    }

    /// Verify a canonical certificate carried by a Noise admission message.
    pub fn verify_certificate_bytes(
        certificate_bytes: &[u8],
        network_name: &str,
        root_fingerprint: &[u8],
        expected_subject_x25519: &[u8],
        expected_role: &str,
        now: i64,
    ) -> Result<CredentialCertificate, CredentialError> {
        let certificate = CredentialCertificate::decode(certificate_bytes)
            .map_err(|_| CredentialError::InvalidBundle)?;
        if certificate.encode_to_vec() != certificate_bytes || expected_subject_x25519.len() != 32 {
            return Err(CredentialError::InvalidBundle);
        }
        let root_public_key = certificate.root_public_key.clone();
        Self::verify_credential_certificate(
            &certificate,
            network_name,
            &root_public_key,
            Some(root_fingerprint),
            now,
        )?;
        if certificate.subject_x25519_public_key != expected_subject_x25519
            || certificate.role != expected_role
        {
            return Err(CredentialError::InvalidBundle);
        }
        Ok(certificate)
    }

    /// Verify signed revocation evidence for a Noise admission message.
    pub fn verify_status_evidence_bytes(
        status_bytes: &[u8],
        network_name: &str,
        root_fingerprint: &[u8],
        certificate_id: &[u8],
        now: i64,
        max_lifetime: Duration,
        minimum_sequence: u64,
    ) -> Result<CredentialCertificateStatus, CredentialError> {
        let status = CredentialCertificateStatus::decode(status_bytes)
            .map_err(|_| CredentialError::InvalidBundle)?;
        if status.encode_to_vec() != status_bytes
            || root_fingerprint.len() != 32
            || certificate_id.len() != CERTIFICATE_ID_LEN
        {
            return Err(CredentialError::InvalidBundle);
        }
        if status.version != CREDENTIAL_STATE_VERSION
            || status.network_name != network_name
            || status.root_fingerprint.as_slice() != root_fingerprint
            || status.root_public_key.len() != 32
            || root_fingerprint_for(&status.root_public_key).as_slice() != root_fingerprint
            || status.certificate_id.as_slice() != certificate_id
            || status.sequence < minimum_sequence
            || status.issued_unix > now.saturating_add(MAX_FUTURE_SKEW)
            || status.not_after_unix <= status.issued_unix
            || status.not_after_unix <= now
            || status.not_after_unix.saturating_sub(status.issued_unix)
                > max_lifetime.as_secs().min(MAX_STATUS_LIFETIME.as_secs()) as i64
            || status.signature.len() != 64
        {
            return Err(
                if status.issued_unix > now.saturating_add(MAX_FUTURE_SKEW) {
                    CredentialError::FutureTimestamp
                } else if status.not_after_unix <= now {
                    CredentialError::Expired
                } else {
                    CredentialError::InvalidBundle
                },
            );
        }
        UnparsedPublicKey::new(&ED25519, &status.root_public_key)
            .verify(&status_signing_bytes(&status), &status.signature)
            .map_err(|_| CredentialError::InvalidSignature)?;
        if status.revoked {
            return Err(CredentialError::Revoked);
        }
        Ok(status)
    }

    pub fn verify_credential_bundle_for_network(
        encoded: &str,
        network_name: &str,
        pinned_root_fingerprint: Option<&[u8]>,
        now: i64,
    ) -> Result<CredentialBundle, CredentialError> {
        let bundle = Self::parse_credential_bundle(encoded)?;
        if bundle.network_name != network_name {
            return Err(CredentialError::WrongNetwork);
        }
        if let Some(pinned) = pinned_root_fingerprint
            && pinned != bundle.root_fingerprint.as_slice()
        {
            return Err(CredentialError::WrongRoot);
        }
        Self::verify_credential_bundle(encoded, network_name, &bundle.root_public_key, now)
    }

    pub fn encode_credential_bundle(bundle: &CredentialBundle) -> String {
        encode_bundle(bundle)
    }

    pub fn verify_revocation_state(
        encoded: &str,
        network_name: &str,
        root_public_key: &[u8],
        minimum_version: u64,
    ) -> Result<CredentialRevocationState, CredentialError> {
        Self::verify_revocation_state_at(
            encoded,
            network_name,
            root_public_key,
            minimum_version,
            current_unix_timestamp(),
        )
    }

    pub fn verify_revocation_state_at(
        encoded: &str,
        network_name: &str,
        root_public_key: &[u8],
        minimum_version: u64,
        now: i64,
    ) -> Result<CredentialRevocationState, CredentialError> {
        if root_public_key.len() != 32 {
            return Err(CredentialError::WrongRoot);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CredentialError::InvalidEncoding)?;
        let state = CredentialRevocationState::decode(bytes.as_slice())
            .map_err(|_| CredentialError::InvalidBundle)?;
        if state.encode_to_vec() != bytes {
            return Err(CredentialError::InvalidBundle);
        }
        if state.version != CREDENTIAL_STATE_VERSION
            || state.network_name != network_name
            || state.root_public_key.as_slice() != root_public_key
            || state.root_fingerprint.as_slice() != root_fingerprint_for(root_public_key).as_slice()
            || state.issued_unix < now.saturating_sub(MAX_REVOCATION_AGE)
            || state.issued_unix > now.saturating_add(MAX_FUTURE_SKEW)
            || !state.revoked_serials.is_empty()
            || state.revoked_certificate_ids.iter().any(|certificate_id| {
                certificate_id.len() != CERTIFICATE_ID_LEN
                    || certificate_id.iter().all(|byte| *byte == 0)
            })
        {
            return Err(if state.issued_unix > now.saturating_add(MAX_FUTURE_SKEW) {
                CredentialError::FutureTimestamp
            } else if state.issued_unix < now.saturating_sub(MAX_REVOCATION_AGE) {
                CredentialError::Expired
            } else {
                CredentialError::WrongRoot
            });
        }
        if state.state_version < minimum_version
            || !state
                .revoked_certificate_ids
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(CredentialError::InvalidStateVersion);
        }
        UnparsedPublicKey::new(&ED25519, root_public_key)
            .verify(&revocation_signing_bytes(&state), &state.signature)
            .map_err(|_| CredentialError::InvalidSignature)?;
        Ok(state)
    }

    pub fn verify_revocation_state_for_bundle(
        encoded: &str,
        bundle: &CredentialBundle,
        minimum_version: u64,
    ) -> Result<CredentialRevocationState, CredentialError> {
        let state = Self::verify_revocation_state(
            encoded,
            &bundle.network_name,
            &bundle.root_public_key,
            minimum_version,
        )?;
        if state.root_fingerprint != bundle.root_fingerprint {
            return Err(CredentialError::WrongRoot);
        }
        Ok(state)
    }

    pub fn apply_revocation_state(&self, encoded: &str) -> Result<(), CredentialError> {
        let state =
            Self::verify_revocation_state(encoded, &self.network_name, &self.root_public_key, 0)?;
        let mut store = self.credentials.lock().unwrap();
        let previous_len = store.revoked_certificate_ids.len();
        store
            .revoked_certificate_ids
            .extend(state.revoked_certificate_ids);
        let previous_version = store.revocation_state_version;
        store.revocation_state_version = previous_version.max(state.state_version);
        if previous_len == store.revoked_certificate_ids.len()
            && previous_version == store.revocation_state_version
        {
            return Ok(());
        }
        drop(store);
        self.save_to_disk();
        Ok(())
    }

    pub fn is_certificate_id_revoked(&self, certificate_id: &[u8]) -> bool {
        self.credentials
            .lock()
            .unwrap()
            .revoked_certificate_ids
            .contains(certificate_id)
    }

    fn save_to_disk(&self) {
        let Some(path) = &self.storage_path else {
            return;
        };
        let store = self.credentials.lock().unwrap();
        let Ok(json) = serde_json::to_string_pretty(&*store) else {
            return;
        };
        if let Err(error) = Self::write_private_file(path, json.as_bytes()) {
            tracing::warn!(?error, "failed to save credentials to disk");
        }
    }

    fn write_private_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
        if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "credential path must not be a symbolic link",
            ));
        }

        let mut temporary = path.as_os_str().to_os_string();
        temporary.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
        let temporary = std::path::PathBuf::from(temporary);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options.open(&temporary)?;
            file.write_all(contents)?;
            file.sync_all()?;
            #[cfg(unix)]
            std::fs::set_permissions(&temporary, {
                use std::os::unix::fs::PermissionsExt;
                std::fs::Permissions::from_mode(0o600)
            })?;
            std::fs::rename(&temporary, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    fn load_from_disk(&self) {
        let Some(path) = &self.storage_path else {
            return;
        };
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return;
        };
        if metadata.file_type().is_symlink() {
            tracing::warn!(path = %path.display(), "refuse symbolic-link credential file");
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                tracing::warn!(path = %path.display(), "refuse credential file with broad permissions");
                return;
            }
        }
        let Ok(data) = std::fs::read_to_string(path) else {
            return;
        };
        match serde_json::from_str::<CredentialStore>(&data) {
            Ok(store) => {
                *self.credentials.lock().unwrap() = store;
                tracing::info!("loaded credentials from {}", path.display());
            }
            Err(error) => tracing::warn!(?error, "failed to parse credentials file"),
        }
    }

    fn decode_pubkey_b64(s: &str) -> Option<Vec<u8>> {
        let decoded = BASE64_STANDARD.decode(s).ok()?;
        (decoded.len() == 32).then_some(decoded)
    }
}

fn derive_root_seed(network_name: &str, network_secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_SEED_DOMAIN);
    hasher.update((network_name.len() as u64).to_be_bytes());
    hasher.update(network_name.as_bytes());
    hasher.update((network_secret.len() as u64).to_be_bytes());
    hasher.update(network_secret.as_bytes());
    hasher.finalize().into()
}

fn root_fingerprint_for(root_public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_FINGERPRINT_DOMAIN);
    hasher.update((root_public_key.len() as u64).to_be_bytes());
    hasher.update(root_public_key);
    hasher.finalize().into()
}

fn canonical_strings_checked(values: Vec<String>) -> Result<Vec<String>, CredentialError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(CredentialError::InvalidBundle);
    }
    let mut sorted = values;
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CredentialError::DuplicatePolicyValue);
    }
    Ok(sorted)
}

fn is_canonical_strings(values: &[String]) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn certificate_signing_bytes(certificate: &CredentialCertificate) -> Vec<u8> {
    let mut unsigned = certificate.clone();
    unsigned.signature.clear();
    let mut bytes = CERTIFICATE_DOMAIN.to_vec();
    bytes.extend_from_slice(&unsigned.encode_to_vec());
    bytes
}

fn revocation_signing_bytes(state: &CredentialRevocationState) -> Vec<u8> {
    let mut unsigned = state.clone();
    unsigned.signature.clear();
    let mut bytes = REVOCATION_DOMAIN.to_vec();
    bytes.extend_from_slice(&unsigned.encode_to_vec());
    bytes
}

fn status_signing_bytes(status: &CredentialCertificateStatus) -> Vec<u8> {
    let mut unsigned = status.clone();
    unsigned.signature.clear();
    let mut bytes = STATUS_DOMAIN.to_vec();
    bytes.extend_from_slice(&unsigned.encode_to_vec());
    bytes
}

fn encode_bundle(bundle: &CredentialBundle) -> String {
    URL_SAFE_NO_PAD.encode(bundle.encode_to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_derivation_is_domain_separated_and_stable() {
        let a = CredentialManager::new_with_network(None, "net", Some("secret"));
        let b = CredentialManager::new_with_network(None, "net", Some("secret"));
        let c = CredentialManager::new_with_network(None, "other", Some("secret"));
        assert_eq!(a.root_public_key(), b.root_public_key());
        assert_ne!(a.root_public_key(), c.root_public_key());
    }

    #[test]
    fn bundle_round_trip_and_tamper_detection() {
        let manager = CredentialManager::new_with_network(None, "net", Some("secret"));
        let (_, encoded) = manager
            .generate_credential_bundle(
                vec!["ops".into()],
                true,
                vec!["10.0.0.0/8".into()],
                Duration::from_secs(3600),
                None,
                true,
            )
            .unwrap();
        let bundle = CredentialManager::verify_credential_bundle(
            &encoded,
            "net",
            manager.root_public_key(),
            current_unix_timestamp(),
        )
        .unwrap();
        assert_eq!(bundle.groups, vec!["ops"]);
        let mut bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = URL_SAFE_NO_PAD.encode(bytes);
        assert!(CredentialManager::parse_credential_bundle(&tampered).is_ok());
        assert!(
            CredentialManager::verify_credential_bundle(
                &tampered,
                "net",
                manager.root_public_key(),
                current_unix_timestamp(),
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_network_and_root_are_rejected() {
        let manager = CredentialManager::new_with_network(None, "net", Some("secret"));
        let (_, encoded) = manager
            .generate_credential_bundle(
                vec![],
                false,
                vec![],
                Duration::from_secs(3600),
                None,
                true,
            )
            .unwrap();
        assert_eq!(
            CredentialManager::verify_credential_bundle(
                &encoded,
                "other",
                manager.root_public_key(),
                current_unix_timestamp(),
            ),
            Err(CredentialError::WrongNetwork)
        );
        assert_eq!(
            CredentialManager::verify_credential_bundle(
                &encoded,
                "net",
                &[0_u8; 32],
                current_unix_timestamp(),
            ),
            Err(CredentialError::WrongRoot)
        );
    }

    #[test]
    fn revocation_state_has_monotonic_signed_version() {
        let manager = CredentialManager::new_with_network(None, "net", Some("secret"));
        let (id, _) = manager
            .generate_credential_bundle(
                vec![],
                false,
                vec![],
                Duration::from_secs(3600),
                None,
                true,
            )
            .unwrap();
        let first = manager.revocation_state().unwrap();
        manager.try_revoke_credential(&id).unwrap();
        let second = manager.revocation_state().unwrap();
        let first_state =
            CredentialManager::verify_revocation_state(&first, "net", manager.root_public_key(), 0)
                .unwrap();
        let second_state = CredentialManager::verify_revocation_state(
            &second,
            "net",
            manager.root_public_key(),
            1,
        )
        .unwrap();
        assert!(second_state.state_version > first_state.state_version);
        assert_eq!(second_state.revoked_certificate_ids.len(), 1);
    }

    #[test]
    fn verifier_manager_cannot_issue_or_sign() {
        let issuer = CredentialManager::new_with_network(None, "net", Some("secret"));
        let (_, encoded) = issuer
            .generate_credential_bundle(
                vec![],
                false,
                vec![],
                Duration::from_secs(3600),
                None,
                true,
            )
            .unwrap();
        let verifier =
            CredentialManager::new_with_network_and_bundle(None, "net", None, Some(&encoded))
                .unwrap();
        assert_eq!(
            verifier.generate_credential(vec![], false, vec![], Duration::from_secs(60)),
            Err(CredentialError::IssuerUnavailable)
        );
        assert_eq!(
            verifier.new_admin_certificate(&[7_u8; 32], Duration::from_secs(60)),
            Err(CredentialError::IssuerUnavailable)
        );
        assert_eq!(
            verifier.revocation_state(),
            Err(CredentialError::IssuerUnavailable)
        );
    }

    #[test]
    fn issuance_rejects_duplicate_policy_values() {
        let issuer = CredentialManager::new_with_network(None, "net", Some("secret"));
        assert_eq!(
            issuer.generate_credential(
                vec!["ops".into(), "ops".into()],
                false,
                vec![],
                Duration::from_secs(60),
            ),
            Err(CredentialError::DuplicatePolicyValue)
        );
        assert_eq!(
            issuer.generate_credential(
                vec![],
                false,
                vec!["10.0.0.0/8".into(), "10.0.0.0/8".into()],
                Duration::from_secs(60),
            ),
            Err(CredentialError::DuplicatePolicyValue)
        );
    }

    #[test]
    fn certificate_status_is_short_lived_and_signed() {
        let path = std::env::temp_dir().join(format!(
            "lowertier-credential-status-{}.json",
            uuid::Uuid::new_v4()
        ));
        let issuer = CredentialManager::new_with_network(Some(path.clone()), "net", Some("secret"));
        let (credential_id, encoded) = issuer
            .generate_credential_bundle(
                vec![],
                false,
                vec![],
                Duration::from_secs(3600),
                None,
                true,
            )
            .unwrap();
        let before_status = std::fs::read(&path).unwrap();
        let bundle = CredentialManager::parse_credential_bundle(&encoded).unwrap();
        let certificate_id = bundle.certificate_id.clone();
        let status = issuer
            .new_admin_certificate_status(&certificate_id, MAX_STATUS_LIFETIME)
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before_status);
        assert!(status.not_after_unix - status.issued_unix <= 60);
        let verified = CredentialManager::verify_status_evidence_bytes(
            &status.encode_to_vec(),
            "net",
            issuer.root_fingerprint(),
            &certificate_id,
            current_unix_timestamp(),
            MAX_STATUS_LIFETIME,
            status.sequence,
        )
        .unwrap();
        assert_eq!(verified.certificate_id, certificate_id);

        assert!(issuer.try_revoke_credential(&credential_id).unwrap());
        let revoked = issuer
            .new_admin_certificate_status(&verified.certificate_id, MAX_STATUS_LIFETIME)
            .unwrap();
        assert_eq!(
            CredentialManager::verify_status_evidence_bytes(
                &revoked.encode_to_vec(),
                "net",
                issuer.root_fingerprint(),
                &verified.certificate_id,
                current_unix_timestamp(),
                MAX_STATUS_LIFETIME,
                revoked.sequence,
            ),
            Err(CredentialError::Revoked)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn divergent_admin_revocations_union_at_equal_version() {
        let admin_a = CredentialManager::new_with_network(None, "net", Some("secret"));
        let admin_b = CredentialManager::new_with_network(None, "net", Some("secret"));
        let (_, bundle_a) = admin_a
            .generate_credential_bundle(
                vec![],
                false,
                vec![],
                Duration::from_secs(3600),
                None,
                true,
            )
            .unwrap();
        let (_, bundle_b) = admin_b
            .generate_credential_bundle(
                vec![],
                false,
                vec![],
                Duration::from_secs(3600),
                None,
                true,
            )
            .unwrap();
        let id_a = CredentialManager::parse_credential_bundle(&bundle_a)
            .unwrap()
            .certificate_id;
        let id_b = CredentialManager::parse_credential_bundle(&bundle_b)
            .unwrap()
            .certificate_id;
        assert!(
            admin_a
                .try_revoke_credential(
                    &admin_a
                        .list_credentials()
                        .first()
                        .expect("credential exists")
                        .credential_id,
                )
                .unwrap()
        );
        assert!(
            admin_b
                .try_revoke_credential(
                    &admin_b
                        .list_credentials()
                        .first()
                        .expect("credential exists")
                        .credential_id,
                )
                .unwrap()
        );
        let verifier =
            CredentialManager::new_with_network_and_bundle(None, "net", None, Some(&bundle_a))
                .unwrap();
        verifier
            .apply_revocation_state(&admin_a.revocation_state().unwrap())
            .unwrap();
        verifier
            .apply_revocation_state(&admin_b.revocation_state().unwrap())
            .unwrap();
        assert!(verifier.is_certificate_id_revoked(&id_a));
        assert!(verifier.is_certificate_id_revoked(&id_b));
        assert_eq!(
            verifier
                .credentials
                .lock()
                .unwrap()
                .revocation_state_version,
            1
        );
    }

    #[test]
    fn revocation_version_exhaustion_preserves_credential() {
        let issuer = CredentialManager::new_with_network(None, "net", Some("secret"));
        let (id, _) = issuer
            .generate_credential_bundle(
                vec![],
                false,
                vec![],
                Duration::from_secs(3600),
                None,
                true,
            )
            .unwrap();
        issuer.credentials.lock().unwrap().revocation_state_version = u64::MAX;
        assert_eq!(
            issuer.try_revoke_credential(&id),
            Err(CredentialError::InvalidStateVersion)
        );
        assert_eq!(issuer.list_credentials().len(), 1);
    }
}
