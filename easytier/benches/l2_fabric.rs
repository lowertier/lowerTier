use std::{hint::black_box, time::Duration};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use easytier::peers::l2_fabric::L2Fabric;

const FRAME_LEN: usize = 1514;

fn ethernet_frame(destination: [u8; 6], source: [u8; 6]) -> Vec<u8> {
    let mut frame = vec![0_u8; FRAME_LEN];
    frame[..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&source);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame
}

fn bench_known_unicast_lookup(c: &mut Criterion) {
    let fabric = L2Fabric::new(16_384, Duration::from_secs(300), 64 * 1024 * 1024);
    let destination = [0x02, 0, 0, 0, 0, 42];
    fabric.learn_source(&ethernet_frame([0xff; 6], destination), 7);
    let frame = ethernet_frame(destination, [0x02, 0, 0, 0, 0, 1]);

    let mut group = c.benchmark_group("l2_fabric_known_unicast_lookup");
    group.throughput(Throughput::Bytes(FRAME_LEN as u64));
    group.bench_function("1514_bytes", |bench| {
        bench.iter(|| black_box(fabric.destination(black_box(&frame)).unwrap()))
    });
    group.finish();
}

criterion_group!(benches, bench_known_unicast_lookup);
criterion_main!(benches);
