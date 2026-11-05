use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio_util::task::AbortOnDropHandle;

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
pub(crate) mod transport_proxy;

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
    cidr_set: Arc<ArcSwap<Vec<(cidr::Ipv4Cidr, cidr::Ipv4Cidr)>>>,
    _updater: AbortOnDropHandle<()>,
}

impl CidrSet {
    pub fn new(global_ctx: ArcGlobalCtx) -> Arc<Self> {
        global_ctx
            .proxy_cidrs
            .get_or_init(|| {
                let mut last_cidrs = global_ctx.config.get_proxy_cidrs();
                let cidr_set = Arc::new(ArcSwap::from_pointee(cidr_mappings(&last_cidrs)));
                let snapshot = cidr_set.clone();
                let context = Arc::downgrade(&global_ctx);
                let updater = tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        let Some(context) = context.upgrade() else {
                            break;
                        };
                        let cidrs = context.config.get_proxy_cidrs();
                        if cidrs != last_cidrs {
                            snapshot.store(Arc::new(cidr_mappings(&cidrs)));
                            last_cidrs = cidrs;
                        }
                    }
                });
                Arc::new(Self {
                    cidr_set,
                    _updater: AbortOnDropHandle::new(updater),
                })
            })
            .clone()
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

    #[tokio::test]
    async fn proxy_protocols_share_initial_and_updated_cidr_mappings() {
        use crate::common::{
            config::{ConfigLoader, TomlConfigLoader},
            global_ctx::GlobalCtx,
        };

        let config = TomlConfigLoader::default();
        let mapped = "172.20.0.0/16".parse().unwrap();
        let real = "10.20.0.0/16".parse().unwrap();
        config.add_proxy_cidr(real, Some(mapped)).unwrap();
        let context = Arc::new(GlobalCtx::new(config));
        let tcp = CidrSet::new(context.clone());
        let udp = CidrSet::new(context.clone());
        assert!(Arc::ptr_eq(&tcp, &udp));
        let ip = "172.20.0.5".parse().unwrap();
        let mut translated = ip;
        assert!(tcp.contains_v4(ip, &mut translated));
        assert_eq!(
            translated,
            "10.20.0.5".parse::<std::net::Ipv4Addr>().unwrap()
        );

        let other = Arc::new(GlobalCtx::new(TomlConfigLoader::default()));
        let other_set = CidrSet::new(other);
        assert!(!Arc::ptr_eq(&tcp, &other_set));
        assert!(other_set.is_empty());

        context.config.clear_proxy_cidrs();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !tcp.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(udp.is_empty());
        let weak = Arc::downgrade(&context);
        drop(context);
        assert!(
            weak.upgrade().is_none(),
            "The updater must not retain the instance"
        );
    }
}
