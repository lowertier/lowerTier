use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::task::JoinSet;

use crate::common::{config::ProxyNetworkConfig, global_ctx::ArcGlobalCtx};

pub mod icmp_proxy;
pub mod ip_reassembler;
pub mod tcp_proxy;
#[cfg(feature = "smoltcp")]
pub mod tokio_smoltcp;
pub mod udp_proxy;

#[cfg(feature = "socks5")]
pub mod fast_socks5;
#[cfg(feature = "socks5")]
pub mod http_proxy;
#[cfg(feature = "socks5")]
pub mod socks5;

pub mod overlay_stream;

fn cidr_mappings(cidrs: &[ProxyNetworkConfig]) -> Vec<(cidr::Ipv4Cidr, cidr::Ipv4Cidr)> {
    let mut mappings = Vec::with_capacity(cidrs.len());
    for cidr in cidrs {
        let mapped = cidr.mapped_cidr.unwrap_or(cidr.cidr);
        if let Some((_, real)) = mappings.iter_mut().find(|(network, _)| *network == mapped) {
            // Preserve the last translation without changing first-match network order.
            if mapped != cidr.cidr {
                *real = cidr.cidr;
            }
        } else {
            mappings.push((mapped, cidr.cidr));
        }
    }
    mappings
}

#[derive(Debug)]
pub(crate) struct CidrSet {
    global_ctx: ArcGlobalCtx,
    cidr_set: Arc<ArcSwap<Vec<(cidr::Ipv4Cidr, cidr::Ipv4Cidr)>>>,
    tasks: JoinSet<()>,
}

impl CidrSet {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        let mut ret = Self {
            global_ctx,
            cidr_set: Arc::new(ArcSwap::from_pointee(vec![])),
            tasks: JoinSet::new(),
        };
        ret.run_cidr_updater();
        ret
    }

    fn run_cidr_updater(&mut self) {
        let global_ctx = self.global_ctx.clone();
        let cidr_set = self.cidr_set.clone();
        self.tasks.spawn(async move {
            let mut last_cidrs = vec![];
            loop {
                let cidrs = global_ctx.config.get_proxy_cidrs();
                if cidrs != last_cidrs {
                    last_cidrs = cidrs.clone();
                    cidr_set.store(Arc::new(cidr_mappings(&cidrs)));
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    pub fn contains_v4(&self, ipv4: std::net::Ipv4Addr, real_ip: &mut std::net::Ipv4Addr) -> bool {
        let ip = ipv4;
        let s = self.cidr_set.load();
        for (cidr, real_cidr) in s.iter() {
            if cidr.contains(&ip) {
                if cidr != real_cidr {
                    let origin_network_bits = real_cidr.first().address().to_bits();
                    let network_mask = cidr.mask().to_bits();

                    let mut converted_ip = ipv4.to_bits();
                    converted_ip &= !network_mask;
                    converted_ip |= origin_network_bits;

                    *real_ip = std::net::Ipv4Addr::from(converted_ip);
                } else {
                    *real_ip = ipv4;
                }
                return true;
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.cidr_set.load().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cidr_mapping_snapshot_consistency() {
        let global_ctx = Arc::new(crate::common::global_ctx::GlobalCtx::new(
            crate::common::config::TomlConfigLoader::default(),
        ));
        let set = CidrSet::new(global_ctx);
        let mapped = "172.20.0.0/16".parse().unwrap();
        let old_real = "10.20.0.0/16".parse().unwrap();
        let new_real = "10.30.0.0/16".parse().unwrap();
        let cidrs = [old_real, new_real, mapped].map(|cidr| ProxyNetworkConfig {
            cidr,
            mapped_cidr: Some(mapped),
            allow: None,
        });
        assert_eq!(cidr_mappings(&cidrs), vec![(mapped, new_real)]);
        set.cidr_set.store(Arc::new(vec![(mapped, old_real)]));
        let old_snapshot = set.cidr_set.load_full();
        let mappings = set.cidr_set.clone();
        let writer = std::thread::spawn(move || {
            for index in 0..10_000 {
                let real = if index % 2 == 0 { old_real } else { new_real };
                mappings.store(Arc::new(vec![(mapped, real)]));
            }
        });
        let ip = "172.20.0.5".parse().unwrap();
        for _ in 0..10_000 {
            let mut real = ip;
            assert!(set.contains_v4(ip, &mut real));
            assert!(
                real == std::net::Ipv4Addr::new(10, 20, 0, 5)
                    || real == std::net::Ipv4Addr::new(10, 30, 0, 5)
            );
        }
        writer.join().unwrap();
        assert_eq!(*old_snapshot, vec![(mapped, old_real)]);
    }
}
