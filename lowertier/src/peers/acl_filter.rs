use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::{
    net::IpAddr,
    sync::{Arc, LazyLock, atomic::AtomicBool},
};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::Mutex;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::{
    Packet as _,
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    udp::UdpPacket,
};
use quanta::Instant;

use crate::proto::acl::{AclStats, Protocol};
use crate::tunnel::packet_def::PacketType;
use crate::{
    common::acl_processor::{AclProcessor, AclResult, AclStatKey, AclStatType, PacketInfo},
    proto::acl::{Acl, Action, ChainType},
    tunnel::packet_def::ZCPacket,
};
use tokio_util::task::AbortOnDropHandle;

static EMPTY_GROUPS: LazyLock<Arc<Vec<String>>> = LazyLock::new(|| Arc::new(Vec::new()));

#[derive(Debug, Eq, PartialEq, Hash)]
struct OutboundAllowRecord {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: Protocol,
}

impl OutboundAllowRecord {
    fn new_from_inbound_packet(p: &PacketInfo) -> Self {
        Self {
            src_ip: p.src_ip,
            dst_ip: p.dst_ip,
            src_port: p.src_port,
            dst_port: p.dst_port,
            protocol: p.protocol,
        }
    }

    fn new_from_outbound_packet(p: &PacketInfo) -> Self {
        Self {
            src_ip: p.dst_ip,
            dst_ip: p.src_ip,
            src_port: p.dst_port,
            dst_port: p.src_port,
            protocol: p.protocol,
        }
    }
}

/// ACL filter that can be inserted into the packet processing pipeline
/// Optimized with lock-free hot reloading via atomic processor replacement
pub struct AclFilter {
    // Use ArcSwap for lock-free atomic replacement during hot reload
    acl_processor: ArcSwap<AclProcessor>,
    acl_enabled: AtomicBool,

    // Track allowed outbound packets and automatically allow their corresponding inbound response
    // packets, even if they would normally be dropped by ACL rules
    outbound_allow_records: Arc<DashMap<OutboundAllowRecord, Instant>>,
    clean_task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl Default for AclFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl AclFilter {
    pub fn new() -> Self {
        let outbound_allow_records = Arc::new(DashMap::new());
        Self {
            acl_processor: ArcSwap::from(Arc::new(AclProcessor::new_disabled())),
            acl_enabled: AtomicBool::new(false),
            outbound_allow_records,
            clean_task: Mutex::new(None),
        }
    }

    fn start_allow_record_cleanup(&self) {
        let mut clean_task = self.clean_task.lock();
        if clean_task.is_some() {
            return;
        }

        let records = self.outbound_allow_records.clone();
        *clean_task = Some(AbortOnDropHandle::new(tokio::spawn(async move {
            let max_life = std::time::Duration::from_secs(30);
            loop {
                records.retain(|_, timestamp| timestamp.elapsed() < max_life);
                tokio::time::sleep(max_life).await;
            }
        })));
    }

    /// Hot reload ACL rules by creating a new processor instance
    /// Preserves connection tracking and rate limiting state across reloads
    /// Now lock-free and doesn't require &mut self!
    pub fn reload_rules(&self, acl_config: Option<&Acl>) {
        self.outbound_allow_records.clear();

        let Some(acl_config) = acl_config else {
            self.acl_enabled.store(false, Ordering::Relaxed);
            self.clean_task.lock().take();
            self.acl_processor
                .store(Arc::new(AclProcessor::new_disabled()));
            return;
        };

        // Get current processor to extract shared state
        let current_processor = self.acl_processor.load();
        let (conn_track, rate_limiters, stats) = current_processor.get_shared_state();

        // Create new processor with preserved state
        let new_processor = AclProcessor::new_with_shared_state(
            acl_config.clone(),
            Some(conn_track),
            Some(rate_limiters),
            Some(stats),
        );

        // Atomic replacement - this is completely lock-free!
        self.acl_processor.store(Arc::new(new_processor));
        self.start_allow_record_cleanup();
        self.acl_enabled.store(true, Ordering::Relaxed);

        tracing::info!("ACL rules hot reloaded with preserved state (lock-free)");
    }

    #[cfg(test)]
    fn background_task_count_for_test(&self) -> usize {
        usize::from(self.clean_task.lock().is_some())
            + self.acl_processor.load().background_task_count_for_test()
    }

    /// Get current processor for processing packets
    pub fn get_processor(&self) -> Arc<AclProcessor> {
        self.acl_processor.load_full()
    }

    pub fn get_stats(&self) -> AclStats {
        let processor = self.get_processor();
        let global_stats = processor.get_stats();
        let (conn_track, _, _) = processor.get_shared_state();
        let rules_stats = processor.get_rules_stats();

        AclStats {
            global: global_stats.into_iter().collect(),
            conn_track: conn_track.iter().map(|x| *x.value()).collect(),
            rules: rules_stats,
        }
    }

    /// Extract packet information for ACL processing
    fn extract_packet_info(
        &self,
        packet: &ZCPacket,
        route: &(dyn super::route_trait::Route + Send + Sync + 'static),
        needs_src_groups: bool,
        needs_dst_groups: bool,
    ) -> Option<(PacketInfo, bool)> {
        let payload = packet.payload();

        let src_ip;
        let dst_ip;
        let src_port;
        let dst_port;
        let protocol;
        let tcp_is_initial_syn;

        let ipv4_packet = Ipv4Packet::new(payload)?;
        if ipv4_packet.get_version() == 4 {
            src_ip = IpAddr::V4(ipv4_packet.get_source());
            dst_ip = IpAddr::V4(ipv4_packet.get_destination());
            protocol = ipv4_packet.get_next_level_protocol();

            (src_port, dst_port) = match protocol {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                    let flags = tcp_packet.get_flags();
                    tcp_is_initial_syn = flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK == 0;
                    (
                        Some(tcp_packet.get_source()),
                        Some(tcp_packet.get_destination()),
                    )
                }
                IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv4_packet.payload())?;
                    tcp_is_initial_syn = false;
                    (
                        Some(udp_packet.get_source()),
                        Some(udp_packet.get_destination()),
                    )
                }
                _ => {
                    tcp_is_initial_syn = false;
                    (None, None)
                }
            };
        } else if ipv4_packet.get_version() == 6 {
            let ipv6_packet = Ipv6Packet::new(payload)?;
            src_ip = IpAddr::V6(ipv6_packet.get_source());
            dst_ip = IpAddr::V6(ipv6_packet.get_destination());
            protocol = ipv6_packet.get_next_header();

            (src_port, dst_port) = match protocol {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv6_packet.payload())?;
                    let flags = tcp_packet.get_flags();
                    tcp_is_initial_syn = flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK == 0;
                    (
                        Some(tcp_packet.get_source()),
                        Some(tcp_packet.get_destination()),
                    )
                }
                IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv6_packet.payload())?;
                    tcp_is_initial_syn = false;
                    (
                        Some(udp_packet.get_source()),
                        Some(udp_packet.get_destination()),
                    )
                }
                _ => {
                    tcp_is_initial_syn = false;
                    (None, None)
                }
            };
        } else {
            return None;
        }

        let acl_protocol = match protocol {
            IpNextHeaderProtocols::Tcp => Protocol::Tcp,
            IpNextHeaderProtocols::Udp => Protocol::Udp,
            IpNextHeaderProtocols::Icmp => Protocol::Icmp,
            IpNextHeaderProtocols::Icmpv6 => Protocol::IcmPv6,
            _ => Protocol::Unspecified,
        };

        let src_groups = if needs_src_groups {
            packet
                .get_src_peer_id()
                .map(|peer_id| route.get_peer_groups(peer_id))
                .unwrap_or_else(|| EMPTY_GROUPS.clone())
        } else {
            EMPTY_GROUPS.clone()
        };
        let dst_groups = if needs_dst_groups {
            packet
                .get_dst_peer_id()
                .map(|peer_id| route.get_peer_groups(peer_id))
                .unwrap_or_else(|| EMPTY_GROUPS.clone())
        } else {
            EMPTY_GROUPS.clone()
        };

        Some((
            PacketInfo {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol: acl_protocol,
                packet_size: payload.len(),
                src_groups,
                dst_groups,
            },
            tcp_is_initial_syn,
        ))
    }

    /// Process ACL result and log if needed
    pub fn handle_acl_result(
        &self,
        result: &AclResult,
        packet_info: &PacketInfo,
        chain_type: ChainType,
        processor: &AclProcessor,
    ) {
        if result.should_log
            && let Some(ref log_context) = result.log_context
        {
            let log_message = log_context.to_message();
            tracing::info!(
                src_ip = %packet_info.src_ip,
                dst_ip = %packet_info.dst_ip,
                src_port = packet_info.src_port,
                dst_port = packet_info.dst_port,
                src_group = packet_info.src_groups.join(","),
                dst_group = packet_info.dst_groups.join(","),
                protocol = ?packet_info.protocol,
                action = ?result.action,
                rule = result.matched_rule_str().as_deref().unwrap_or("unknown"),
                chain_type = ?chain_type,
                "ACL: {}", log_message
            );
        }

        // Update global statistics in the ACL processor
        match result.action {
            Action::Allow => {
                processor.increment_stat(AclStatKey::PacketsAllowed);
                processor.increment_stat(AclStatKey::from_chain_and_action(
                    chain_type,
                    AclStatType::Allowed,
                ));
                tracing::trace!("ACL: Packet allowed");
            }
            Action::Drop => {
                processor.increment_stat(AclStatKey::PacketsDropped);
                processor.increment_stat(AclStatKey::from_chain_and_action(
                    chain_type,
                    AclStatType::Dropped,
                ));
                tracing::debug!("ACL: Packet dropped");
            }
            Action::Noop => {
                processor.increment_stat(AclStatKey::PacketsNoop);
                processor.increment_stat(AclStatKey::from_chain_and_action(
                    chain_type,
                    AclStatType::Noop,
                ));
                tracing::trace!("ACL: No operation");
            }
        }

        // Track total packets processed per chain
        processor.increment_stat(AclStatKey::from_chain_and_action(
            chain_type,
            AclStatType::Total,
        ));
        processor.increment_stat(AclStatKey::PacketsTotal);
    }

    fn classify_chain_type(
        is_in: bool,
        packet_info: &PacketInfo,
        my_ipv4: Option<Ipv4Addr>,
        is_local_ipv6: impl Fn(Ipv6Addr) -> bool,
    ) -> ChainType {
        if !is_in {
            return ChainType::Outbound;
        }

        let is_local_dst = packet_info.dst_ip == my_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED)
            || matches!(packet_info.dst_ip, IpAddr::V6(dst) if is_local_ipv6(dst));

        if is_local_dst {
            ChainType::Inbound
        } else {
            ChainType::Forward
        }
    }

    fn needs_response_record(protocol: Protocol) -> bool {
        protocol != Protocol::Tcp
    }

    fn allow_untracked_tcp_reply(
        chain_type: ChainType,
        protocol: Protocol,
        tcp_is_initial_syn: bool,
    ) -> bool {
        chain_type == ChainType::Inbound && protocol == Protocol::Tcp && !tcp_is_initial_syn
    }

    /// Common ACL processing logic
    pub fn process_packet_with_acl(
        &self,
        packet: &ZCPacket,
        is_in: bool,
        my_ipv4: Option<Ipv4Addr>,
        is_local_ipv6: impl Fn(Ipv6Addr) -> bool,
        route: &(dyn super::route_trait::Route + Send + Sync + 'static),
    ) -> bool {
        if !self.acl_enabled.load(Ordering::Relaxed) {
            return true;
        }

        if packet.peer_manager_header().unwrap().packet_type != PacketType::Data as u8 {
            return true;
        }

        let processor = self.acl_processor.load();
        let (packet_info, tcp_is_initial_syn) = match self.extract_packet_info(
            packet,
            route,
            processor.needs_src_groups(),
            processor.needs_dst_groups(),
        ) {
            Some(info) => info,
            None => {
                tracing::warn!(
                    "Failed to extract packet info from {:?} packet, header: {:?}",
                    if is_in { "inbound" } else { "outbound" },
                    packet.peer_manager_header()
                );
                // allow all unknown packets
                return true;
            }
        };

        let chain_type = Self::classify_chain_type(is_in, &packet_info, my_ipv4, is_local_ipv6);

        let acl_result = processor.process_packet(&packet_info, chain_type);

        self.handle_acl_result(&acl_result, &packet_info, chain_type, &processor);

        // Check if packet should be allowed
        match acl_result.action {
            Action::Allow | Action::Noop => {
                if matches!(chain_type, ChainType::Outbound)
                    && Self::needs_response_record(packet_info.protocol)
                {
                    self.outbound_allow_records.insert(
                        OutboundAllowRecord::new_from_outbound_packet(&packet_info),
                        Instant::now(),
                    );
                }
                true
            }
            Action::Drop => {
                if Self::allow_untracked_tcp_reply(
                    chain_type,
                    packet_info.protocol,
                    tcp_is_initial_syn,
                ) {
                    return true;
                }

                if is_in {
                    let record = OutboundAllowRecord::new_from_inbound_packet(&packet_info);
                    let entry = self.outbound_allow_records.entry(record);
                    if let dashmap::Entry::Occupied(mut entry) = entry {
                        entry.insert(Instant::now());
                        tracing::trace!(
                            "ACL: Allowing {:?} packet from {} to {} because of existing allow record, chain_type: {:?}",
                            packet_info.protocol,
                            packet_info.src_ip,
                            packet_info.dst_ip,
                            chain_type,
                        );
                        return true;
                    }
                }

                tracing::trace!(
                    "ACL: Dropping {:?} packet from {} to {}, chain_type: {:?}",
                    packet_info.protocol,
                    packet_info.src_ip,
                    packet_info.dst_ip,
                    chain_type,
                );

                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use quanta::Instant;

    use crate::{
        common::acl_processor::PacketInfo,
        proto::acl::{Acl, ChainType, Protocol},
    };

    use super::{AclFilter, OutboundAllowRecord};

    fn packet_info(dst_ip: IpAddr) -> PacketInfo {
        PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip,
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: Protocol::Tcp,
            packet_size: 64,
            src_groups: Arc::new(Vec::new()),
            dst_groups: Arc::new(Vec::new()),
        }
    }

    #[test]
    fn classify_chain_type_treats_public_ipv6_lease_as_inbound() {
        let leased_ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 0x123);
        let packet_info = packet_info(IpAddr::V6(leased_ipv6));

        let chain =
            AclFilter::classify_chain_type(true, &packet_info, None, |ip| ip == leased_ipv6);

        assert_eq!(chain, ChainType::Inbound);
    }

    #[test]
    fn classify_chain_type_keeps_non_local_ipv6_as_forward() {
        let leased_ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 0x123);
        let packet_info = packet_info(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xffff, 2, 0, 0, 0, 0x100,
        )));

        let chain =
            AclFilter::classify_chain_type(true, &packet_info, None, |ip| ip == leased_ipv6);

        assert_eq!(chain, ChainType::Forward);
    }

    #[tokio::test]
    async fn reload_rules_clears_outbound_allow_records() {
        let filter = AclFilter::new();
        filter.outbound_allow_records.insert(
            OutboundAllowRecord {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                src_port: Some(1234),
                dst_port: Some(80),
                protocol: Protocol::Tcp,
            },
            Instant::now(),
        );
        assert_eq!(filter.outbound_allow_records.len(), 1);

        filter.reload_rules(Some(&Acl::default()));

        assert_eq!(filter.outbound_allow_records.len(), 0);

        filter.outbound_allow_records.insert(
            OutboundAllowRecord {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                src_port: Some(4321),
                dst_port: Some(443),
                protocol: Protocol::Tcp,
            },
            Instant::now(),
        );
        assert_eq!(filter.outbound_allow_records.len(), 1);

        filter.reload_rules(None);

        assert_eq!(filter.outbound_allow_records.len(), 0);
    }

    #[tokio::test]
    async fn disabled_acl_has_no_background_tasks() {
        let filter = AclFilter::new();
        assert_eq!(filter.background_task_count_for_test(), 0);

        filter.reload_rules(Some(&Acl::default()));
        assert_eq!(filter.background_task_count_for_test(), 3);

        filter.reload_rules(None);
        assert_eq!(filter.background_task_count_for_test(), 0);
    }

    #[test]
    fn response_tracking_matches_the_compiled_firewall_model() {
        assert!(!AclFilter::needs_response_record(Protocol::Tcp));
        assert!(AclFilter::needs_response_record(Protocol::Udp));
        assert!(AclFilter::needs_response_record(Protocol::Icmp));

        assert!(AclFilter::allow_untracked_tcp_reply(
            ChainType::Inbound,
            Protocol::Tcp,
            false,
        ));
        assert!(!AclFilter::allow_untracked_tcp_reply(
            ChainType::Inbound,
            Protocol::Tcp,
            true,
        ));
        assert!(!AclFilter::allow_untracked_tcp_reply(
            ChainType::Forward,
            Protocol::Tcp,
            false,
        ));
    }
}
