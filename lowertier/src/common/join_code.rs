//! Join codes: a network name, its network secret or a signed credential, the transport
//! admission secret when one is configured, and bootstrap peer URIs in one copyable string. Any
//! member can produce one; there is no coordination server.
//!
//! The text is `lt1.` followed by unpadded base64url of a small TOML document.

use anyhow::{Context as _, ensure};
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "lt1.";
const MAX_LEN: usize = 16 * 1024;
const MAX_PEERS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinCode {
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    /// `camouflage.admission_secret`. Credential members have no network secret, so transport
    /// admission needs this explicit secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<String>,
    #[serde(default)]
    pub peers: Vec<String>,
}

impl JoinCode {
    fn check(&self) -> anyhow::Result<()> {
        ensure!(!self.network.is_empty(), "the join code names no network");
        ensure!(
            self.secret.is_some() != self.credential.is_some(),
            "a join code carries either a network secret or a credential"
        );
        ensure!(
            self.credential.is_none() || self.admission.is_some(),
            "a credential join code needs a transport admission secret"
        );
        ensure!(
            !self.peers.is_empty(),
            "the join code lists no bootstrap peer"
        );
        ensure!(
            self.peers.len() <= MAX_PEERS,
            "a join code lists at most {MAX_PEERS} peers"
        );
        for peer in &self.peers {
            let uri = url::Url::parse(peer).with_context(|| format!("bootstrap peer {peer:?}"))?;
            ensure!(
                uri.host().is_some() && uri.port().is_some(),
                "bootstrap peer {peer:?} needs a host and a port"
            );
            ensure!(
                !uri
                    .host_str()
                    .is_some_and(|host| host == "0.0.0.0" || host == "[::]"),
                "bootstrap peer {peer:?} has an unspecified address"
            );
        }
        Ok(())
    }

    pub fn encode(&self) -> anyhow::Result<String> {
        self.check()?;
        let text = toml::to_string(self)?;
        Ok(format!("{PREFIX}{}", BASE64_URL_SAFE_NO_PAD.encode(text)))
    }

    pub fn decode(code: &str) -> anyhow::Result<Self> {
        let code = code.trim();
        ensure!(code.len() <= MAX_LEN, "the join code is too long");
        let body = code
            .strip_prefix(PREFIX)
            .context("a join code starts with lt1.")?;
        let text = BASE64_URL_SAFE_NO_PAD
            .decode(body)
            .context("the join code is not valid base64url")?;
        let text = String::from_utf8(text).context("the join code is not UTF-8")?;
        let join: Self = toml::from_str(&text).context("the join code is malformed")?;
        join.check()?;
        Ok(join)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> JoinCode {
        JoinCode {
            network: "office".into(),
            secret: Some("c2VjcmV0".into()),
            credential: None,
            admission: None,
            peers: vec!["quic://203.0.113.7:11012".into()],
        }
    }

    #[test]
    fn round_trips_and_rejects_unusable_codes() {
        let code = sample().encode().unwrap();
        assert!(code.starts_with("lt1."));
        assert_eq!(JoinCode::decode(&format!(" {code}\n")).unwrap(), sample());

        let mut both = sample();
        both.credential = Some("bundle".into());
        assert!(both.encode().is_err());
        let mut credential = sample();
        credential.secret = None;
        credential.credential = Some("bundle".into());
        assert!(credential.encode().is_err(), "credentials need admission");
        credential.admission = Some("transport-admission-key".into());
        let code = credential.encode().unwrap();
        assert_eq!(JoinCode::decode(&code).unwrap(), credential);
        let mut wildcard = sample();
        wildcard.peers = vec!["quic://0.0.0.0:11012".into()];
        assert!(wildcard.encode().is_err());
        let mut none = sample();
        none.peers.clear();
        assert!(none.encode().is_err());
        assert!(JoinCode::decode("lt2.abc").is_err());
        assert!(JoinCode::decode("lt1.!!").is_err());
    }
}
