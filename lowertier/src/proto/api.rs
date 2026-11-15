pub mod control {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/api.control.v1.rs"));
        include!(concat!(env!("OUT_DIR"), "/api.control.v1.serde.rs"));

        /// Preserve RPC error classes across local, owned, and remote control adapters.
        ///
        /// Invalid JSON identifies the request body. Unknown methods return `not_found`.
        /// Timeouts and closed connections permit retries. Protocol and encoding failures remain internal.
        impl From<crate::proto::rpc_types::error::Error> for ApiError {
            fn from(error: crate::proto::rpc_types::error::Error) -> Self {
                use crate::proto::rpc_types::error::Error;

                let (code, message, field_path) = match error {
                    Error::InvalidJsonRequest(message) => ("invalid_argument", message, "body"),
                    Error::InvalidMethodIndex(_, _) => {
                        ("not_found", "The control method does not exist.".into(), "")
                    }
                    Error::Timeout(_) => (
                        "deadline_exceeded",
                        "The control request exceeded its deadline.".into(),
                        "",
                    ),
                    Error::TunnelError(_) | Error::Shutdown => (
                        "unavailable",
                        "The control connection is unavailable.".into(),
                        "",
                    ),
                    _ => ("internal", "The control RPC failed.".into(), ""),
                };
                Self {
                    code: code.into(),
                    message,
                    field_path: field_path.into(),
                    retryable: matches!(code, "unavailable" | "deadline_exceeded"),
                }
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
