pub(crate) mod client;
mod runtime;
#[cfg(test)]
pub use lowertier_tracker::server;
pub(crate) mod socket;
pub use lowertier_tracker::wire;
pub(crate) use runtime::PathConnections;
pub(crate) use runtime::start;

#[derive(Clone)]
pub(crate) struct DiscoveryObservation {
    pub protocol: String,
    pub socket: std::net::SocketAddr,
    pub observer: String,
    pub endpoint: std::net::SocketAddr,
    pub sampled_at: std::time::Instant,
    pub lifetime: Option<std::time::Duration>,
    pub provisional: bool,
}

pub(crate) fn observer_uri(uri: &url::Url) -> String {
    let mut uri = uri.clone();
    let _ = uri.set_username("");
    let _ = uri.set_password(None);
    uri.set_query(None);
    uri.set_fragment(None);
    uri.to_string()
}
