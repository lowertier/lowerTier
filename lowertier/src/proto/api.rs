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

    impl PeerRoutePair {
        pub fn get_latency_ms(&self) -> Option<f64> {
            let mut ret = u64::MAX;
            let p = self.peer.as_ref()?;
            let default_conn_id = p.default_conn_id.map(|id| id.to_string());
            for conn in p.conns.iter() {
                let Some(stats) = &conn.stats else {
                    continue;
                };
                if default_conn_id == Some(conn.conn_id.to_string()) {
                    return Some(f64::from(stats.latency_us as u32) / 1000.0);
                }
                ret = ret.min(stats.latency_us);
            }

            if ret == u64::MAX {
                None
            } else {
                Some(f64::from(ret as u32) / 1000.0)
            }
        }

        pub fn get_rx_bytes(&self) -> Option<u64> {
            let mut ret = 0;
            let p = self.peer.as_ref()?;
            for conn in p.conns.iter() {
                let Some(stats) = &conn.stats else {
                    continue;
                };
                ret += stats.rx_bytes;
            }

            if ret == 0 { None } else { Some(ret) }
        }

        pub fn get_tx_bytes(&self) -> Option<u64> {
            let mut ret = 0;
            let p = self.peer.as_ref()?;
            for conn in p.conns.iter() {
                let Some(stats) = &conn.stats else {
                    continue;
                };
                ret += stats.tx_bytes;
            }

            if ret == 0 { None } else { Some(ret) }
        }

        pub fn get_loss_rate(&self) -> Option<f64> {
            let p = self.peer.as_ref()?;
            let default_conn_id = p.default_conn_id.map(|id| id.to_string());
            let mut ret = None;
            for conn in p.conns.iter() {
                if default_conn_id == Some(conn.conn_id.to_string()) {
                    return Some(conn.loss_rate as f64);
                }

                ret.get_or_insert(conn.loss_rate as f64);
            }

            ret
        }

        fn selected_speed_connection(&self) -> Option<&PeerConnInfo> {
            let peer = self.peer.as_ref()?;
            let default_conn_id = peer.default_conn_id.map(|id| id.to_string());
            if let Some(connection) = peer
                .conns
                .iter()
                .find(|connection| default_conn_id.as_deref() == Some(&connection.conn_id))
            {
                return Some(connection);
            }
            peer.conns
                .iter()
                .filter(|connection| connection.tx_delivery_bps.is_some())
                .max_by(|left, right| {
                    left.tx_delivery_bps
                        .cmp(&right.tx_delivery_bps)
                        .then_with(|| right.speed_sample_age_ms.cmp(&left.speed_sample_age_ms))
                        .then_with(|| right.conn_id.cmp(&left.conn_id))
                })
        }

        pub fn get_speed_delivery_bps(&self) -> Option<u64> {
            self.selected_speed_connection()?.tx_delivery_bps
        }

        pub fn get_speed_sample_age_ms(&self) -> Option<u64> {
            self.selected_speed_connection()?.speed_sample_age_ms
        }

        fn get_tunnel_proto_str(tunnel_info: &super::super::common::TunnelInfo) -> String {
            tunnel_info.display_tunnel_type()
        }

        pub fn get_conn_protos(&self) -> Option<Vec<String>> {
            let mut ret = vec![];
            let p = self.peer.as_ref()?;
            for conn in p.conns.iter() {
                let Some(tunnel_info) = &conn.tunnel else {
                    continue;
                };
                // insert if not exists
                let tunnel_type = Self::get_tunnel_proto_str(tunnel_info);
                if !ret.contains(&tunnel_type) {
                    ret.push(tunnel_type);
                }
            }

            if ret.is_empty() { None } else { Some(ret) }
        }

        pub fn get_udp_nat_type(&self) -> String {
            use crate::proto::common::NatType;
            let mut ret = NatType::Unknown;
            if let Some(r) = &self.route.clone().unwrap_or_default().stun_info {
                ret = NatType::try_from(r.udp_nat_type).unwrap();
            }
            format!("{:?}", ret)
        }
    }

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

pub mod logger {
    include!(concat!(env!("OUT_DIR"), "/api.logger.rs"));
    include!(concat!(env!("OUT_DIR"), "/api.logger.serde.rs"));
}

pub mod manage {
    include!(concat!(env!("OUT_DIR"), "/api.manage.rs"));
    include!(concat!(env!("OUT_DIR"), "/api.manage.serde.rs"));
}
