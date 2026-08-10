use std::{
    hint::black_box,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use lowertier::{
    common::acl_processor::{AclProcessor, PacketInfo},
    proto::acl::{Acl, AclV1, Action, Chain, ChainType, Protocol, Rule},
};

fn processor(rule_count: usize) -> AclProcessor {
    let mut rules = Vec::with_capacity(rule_count + 1);
    for index in 0..rule_count {
        rules.push(Rule {
            priority: (rule_count - index + 1) as u32,
            enabled: true,
            protocol: Protocol::Tcp as i32,
            ports: vec!["1".to_owned()],
            action: Action::Drop as i32,
            ..Default::default()
        });
    }
    rules.push(Rule {
        priority: 1,
        enabled: true,
        protocol: Protocol::Tcp as i32,
        ports: vec!["443".to_owned()],
        action: Action::Allow as i32,
        ..Default::default()
    });

    AclProcessor::new(Acl {
        acl_v1: Some(AclV1 {
            chains: vec![Chain {
                chain_type: ChainType::Inbound as i32,
                enabled: true,
                rules,
                default_action: Action::Drop as i32,
                ..Default::default()
            }],
            ..Default::default()
        }),
    })
}

fn packet(source: u32) -> PacketInfo {
    PacketInfo {
        src_ip: IpAddr::V4(Ipv4Addr::from(source)),
        dst_ip: "10.1.0.3".parse::<IpAddr>().unwrap(),
        src_port: Some(40_000),
        dst_port: Some(443),
        protocol: Protocol::Tcp,
        packet_size: 1_200,
        src_groups: Arc::new(Vec::new()),
        dst_groups: Arc::new(Vec::new()),
    }
}

fn bench_acl_filter(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _guard = runtime.enter();
    let mut group = c.benchmark_group("acl_filter");
    group.throughput(Throughput::Elements(1));

    for rule_count in [0, 8, 128, 512] {
        let processor = processor(rule_count);
        let hot_packet = packet(0x0a01_0002);
        group.bench_with_input(
            BenchmarkId::new("hot_flow", rule_count),
            &rule_count,
            |bench, _| {
                bench.iter(|| {
                    black_box(processor.process_packet(black_box(&hot_packet), ChainType::Inbound))
                });
            },
        );

        let mut source = 1_u32;
        group.bench_with_input(
            BenchmarkId::new("flow_churn", rule_count),
            &rule_count,
            |bench, _| {
                bench.iter(|| {
                    source = source.wrapping_add(1).max(1);
                    let packet = packet(source);
                    black_box(processor.process_packet(black_box(&packet), ChainType::Inbound))
                });
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(2))
        .warm_up_time(Duration::from_secs(1))
        .sample_size(30);
    targets = bench_acl_filter
}
criterion_main!(benches);
