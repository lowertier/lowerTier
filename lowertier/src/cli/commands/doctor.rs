use super::super::{
    args::Arguments,
    client::{self, Client, Response},
    error::CliError,
};
use crate::proto::{api::control::v1::*, common::NatType};
use serde::Serialize;

#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Serialize)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    pub fix: Option<String>,
}

#[derive(Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    fn add(
        &mut self,
        name: &'static str,
        level: Level,
        detail: impl Into<String>,
        fix: Option<String>,
    ) {
        self.checks.push(Check {
            name,
            level,
            detail: detail.into(),
            fix,
        });
    }

    pub fn failed(&self) -> bool {
        self.checks.iter().any(|check| check.level == Level::Fail)
    }
}

/// Loss above this share of packets suggests an MTU or path problem.
const HIGH_LOSS_PPM: u32 = 20_000;

fn nat_name(value: i32) -> &'static str {
    NatType::try_from(value).map_or("unknown", |nat| nat.as_str_name())
}

pub async fn run(args: &Arguments) -> Report {
    let mut report = Report { checks: Vec::new() };
    let records = crate::common::runtime_registry::live_records();
    let target = match client::target(args) {
        Ok(target) => target,
        Err(error) => {
            report.add("daemon", Level::Fail, error.0.message, None);
            return report;
        }
    };
    match (&target.name, records.len()) {
        (Some(name), _) => report.add(
            "daemon",
            Level::Ok,
            format!("{name} at {}", target.portal),
            None,
        ),
        (None, 0) => report.add(
            "daemon",
            Level::Warn,
            format!(
                "No running daemon announced itself; trying {}",
                target.portal
            ),
            Some("Start a node with `lowertier run -c FILE`, or pass --portal.".into()),
        ),
        (None, _) => report.add(
            "daemon",
            Level::Ok,
            format!("portal {}", target.portal),
            None,
        ),
    }

    let token_file = target.token_file.clone();
    if args.token.is_none() {
        match client::read_token(&token_file) {
            Ok(_) => report.add(
                "token",
                Level::Ok,
                format!("{} is readable", token_file.display()),
                None,
            ),
            Err(error) => {
                report.add("token", Level::Fail, error.0.message, None);
                return report;
            }
        }
    }

    let mut client = match Client::open(args, target, uuid::Uuid::new_v4().to_string()).await {
        Ok(client) => client,
        Err(error) => {
            report.add(
                "portal",
                Level::Fail,
                error.0.message,
                Some("Check that the daemon runs: `lowertier nodes`.".into()),
            );
            return report;
        }
    };
    let instances = match client
        .rpc
        .list_instances(
            client.controller(),
            ListInstancesRequest {
                meta: client.meta(),
            },
        )
        .await
        .map_err(CliError::from)
        .and_then(|list| match list.error {
            Some(error) => Err(error.into()),
            None => Ok(list.instances),
        }) {
        Ok(instances) => instances,
        Err(error) => {
            let fix = (error.0.code == "permission_denied").then(|| {
                "The token does not match this daemon. Pass the daemon's --token-file.".to_owned()
            });
            report.add("portal", Level::Fail, error.0.message, fix);
            return report;
        }
    };
    report.add(
        "portal",
        Level::Ok,
        format!("{} answers", client.target.portal),
        None,
    );

    for instance in &instances {
        if !instance.last_error.is_empty() {
            report.add(
                "instance",
                Level::Fail,
                format!("{}: {}", instance.name, instance.last_error),
                Some("Fix the error above, then `lowertier instance start`.".into()),
            );
        } else if !instance.running {
            report.add(
                "instance",
                Level::Warn,
                format!("{} is stopped", instance.name),
                Some(format!("lowertier instance start -i {}", instance.name)),
            );
        }
    }
    if instances.is_empty() {
        report.add(
            "instance",
            Level::Fail,
            "The daemon runs no instance",
            Some("lowertier instance create FILE".into()),
        );
        return report;
    }
    match client.select_instance(args.instance.as_deref()).await {
        Ok((id, _)) => client.meta.instance_id = id,
        Err(error) => {
            report.add("instance", Level::Warn, error.0.message, None);
            return report;
        }
    }
    if !report.checks.iter().any(|check| check.name == "instance") {
        let name = instances
            .iter()
            .find(|instance| instance.instance_id == client.meta.instance_id)
            .map_or("", |instance| instance.name.as_str());
        report.add("instance", Level::Ok, format!("{name} is running"), None);
    }

    let status = match super::status::fetch(&client).await {
        Ok(status) => status,
        Err(error) => {
            report.add("instance", Level::Fail, error.0.message, None);
            return report;
        }
    };
    let node = status.node.node.clone().unwrap_or_default();
    if node.version != crate::VERSION {
        report.add(
            "version",
            Level::Warn,
            format!(
                "daemon {} differs from this CLI {}",
                node.version,
                crate::VERSION
            ),
            Some("Restart the daemon with the installed binary.".into()),
        );
    }

    if status.listeners.listeners.is_empty() {
        report.add(
            "listeners",
            Level::Warn,
            "No listener: peers cannot dial this node",
            Some("lowertier listeners add quic://0.0.0.0:11012".into()),
        );
    } else {
        let uris = status
            .listeners
            .listeners
            .iter()
            .map(|listener| listener.uri.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        report.add("listeners", Level::Ok, uris, None);
    }

    let stun = node.stun_info.unwrap_or_default();
    let (udp, tcp) = (nat_name(stun.udp_nat_type), nat_name(stun.tcp_nat_type));
    let public = if stun.public_ip.is_empty() {
        "unknown".into()
    } else {
        stun.public_ip.join(", ")
    };
    if stun.udp_nat_type == NatType::Unknown as i32 {
        report.add(
            "nat",
            Level::Warn,
            format!("UDP NAT type unknown (public address {public})"),
            Some("STUN may be blocked. Check nat.stun, or wait for discovery to finish.".into()),
        );
    } else {
        report.add(
            "nat",
            Level::Ok,
            format!("UDP {udp}, TCP {tcp}, public {public}"),
            None,
        );
    }

    let failing = status
        .discovery
        .trackers
        .iter()
        .filter(|tracker| !tracker.last_error.is_empty())
        .collect::<Vec<_>>();
    if !failing.is_empty() {
        let detail = failing
            .iter()
            .map(|tracker| format!("{}: {}", tracker.uri, tracker.last_error))
            .collect::<Vec<_>>()
            .join("; ");
        report.add(
            "discovery",
            Level::Warn,
            detail,
            Some("Check tracker URLs in discovery.trackers and outbound access.".into()),
        );
    } else if !status.discovery.trackers.is_empty() {
        report.add(
            "discovery",
            Level::Ok,
            format!("{} tracker(s) reachable", status.discovery.trackers.len()),
            None,
        );
    }

    let peers = &status.peers.peers;
    if peers.is_empty() {
        report.add(
            "peers",
            Level::Warn,
            "No peer is connected",
            Some("Add one with `lowertier peers add URI`, or set discovery.trackers.".into()),
        );
    } else {
        let direct = peers.iter().filter(|peer| !peer.conns.is_empty()).count();
        report.add(
            "peers",
            Level::Ok,
            format!("{} peer(s), {direct} direct", peers.len()),
            None,
        );
    }
    let lossy = peers
        .iter()
        .filter(|peer| peer.loss_ppm.is_some_and(|loss| loss > HIGH_LOSS_PPM))
        .map(|peer| {
            let name = peer
                .route
                .as_ref()
                .map_or_else(|| peer.peer_id.to_string(), |route| route.hostname.clone());
            format!(
                "{name} {:.1}%",
                f64::from(peer.loss_ppm.unwrap()) / 10_000.0
            )
        })
        .collect::<Vec<_>>();
    if !lossy.is_empty() {
        report.add(
            "loss",
            Level::Warn,
            format!("High loss: {}", lossy.join(", ")),
            Some("If large packets fail, lower the MTU: lowertier set tun.mtu=1280".into()),
        );
    }
    report
}

pub async fn execute(args: &Arguments) -> (Response, bool) {
    let report = run(args).await;
    let failed = report.failed();
    (Response::Doctor(report), failed)
}
