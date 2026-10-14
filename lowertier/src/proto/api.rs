pub mod control {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/api.control.v1.rs"));
        include!(concat!(env!("OUT_DIR"), "/api.control.v1.serde.rs"));
    }
}

pub mod config {
    include!(concat!(env!("OUT_DIR"), "/api.config.rs"));
    include!(concat!(env!("OUT_DIR"), "/api.config.serde.rs"));

    pub struct Patchable<T> {
        pub action: Option<ConfigPatchAction>,
        pub value: Option<T>,
    }

    impl From<PortForwardPatch> for Patchable<crate::common::config::PortForwardConfig> {
        fn from(patch: PortForwardPatch) -> Self {
            Patchable {
                action: ConfigPatchAction::try_from(patch.action).ok(),
                value: patch.cfg.map(Into::into),
            }
        }
    }

    impl From<RoutePatch> for Patchable<cidr::Ipv4Cidr> {
        fn from(value: RoutePatch) -> Self {
            Patchable {
                action: ConfigPatchAction::try_from(value.action).ok(),
                value: value.cidr.map(Into::into),
            }
        }
    }

    impl From<ExitNodePatch> for Patchable<std::net::IpAddr> {
        fn from(value: ExitNodePatch) -> Self {
            Patchable {
                action: ConfigPatchAction::try_from(value.action).ok(),
                value: value.node.map(Into::into),
            }
        }
    }

    impl From<StringPatch> for Patchable<String> {
        fn from(value: StringPatch) -> Self {
            Patchable {
                action: ConfigPatchAction::try_from(value.action).ok(),
                value: Some(value.value),
            }
        }
    }

    impl From<UrlPatch> for Patchable<url::Url> {
        fn from(value: UrlPatch) -> Self {
            Patchable {
                action: ConfigPatchAction::try_from(value.action).ok(),
                value: value.url.map(Into::into),
            }
        }
    }

    pub fn patch_vec<T>(v: &mut Vec<T>, patches: Vec<Patchable<T>>)
    where
        T: PartialEq,
    {
        for patch in patches {
            match patch.action {
                Some(ConfigPatchAction::Add) => {
                    if let Some(value) = patch.value {
                        v.push(value);
                    }
                }
                Some(ConfigPatchAction::Remove) => {
                    if let Some(value) = patch.value {
                        v.retain(|x| x != &value);
                    }
                }
                Some(ConfigPatchAction::Clear) => {
                    v.clear();
                }
                None => {}
            }
        }
    }
}

pub mod instance {
    include!(concat!(env!("OUT_DIR"), "/api.instance.rs"));
    include!(concat!(env!("OUT_DIR"), "/api.instance.serde.rs"));

    pub fn list_peer_route_pair(peers: Vec<PeerInfo>, routes: Vec<Route>) -> Vec<PeerRoutePair> {
        let mut pairs: Vec<PeerRoutePair> = vec![];

        for route in routes.iter() {
            let peer = peers.iter().find(|peer| peer.peer_id == route.peer_id);
            let pair = PeerRoutePair {
                route: Some(route.clone()),
                peer: peer.cloned(),
            };

            pairs.push(pair);
        }

        pairs.sort_by(|a, b| {
            let a_is_public_server = a
                .route
                .as_ref()
                .and_then(|r| r.feature_flag.as_ref())
                .is_some_and(|f| f.is_public_server);

            let b_is_public_server = b
                .route
                .as_ref()
                .and_then(|r| r.feature_flag.as_ref())
                .is_some_and(|f| f.is_public_server);

            if a_is_public_server != b_is_public_server {
                return if a_is_public_server {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                };
            }

            let a_ip = a
                .route
                .as_ref()
                .and_then(|r| r.ipv4_addr.as_ref())
                .and_then(|ipv4| ipv4.address.as_ref())
                .map_or(0, |addr| addr.addr);

            let b_ip = b
                .route
                .as_ref()
                .and_then(|r| r.ipv4_addr.as_ref())
                .and_then(|ipv4| ipv4.address.as_ref())
                .map_or(0, |addr| addr.addr);

            a_ip.cmp(&b_ip)
        });

        pairs
    }
}

pub mod manage {
    include!(concat!(env!("OUT_DIR"), "/api.manage.rs"));
    include!(concat!(env!("OUT_DIR"), "/api.manage.serde.rs"));
}
