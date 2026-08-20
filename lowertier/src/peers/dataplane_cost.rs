use crate::{
    peers::peer_manager::benchmark_prepare_packet_batch,
    tunnel::{
        batch::PacketBatch,
        packet_def::{PacketType, ZCPacket},
    },
};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use std::{
    fs::File,
    hint::black_box,
    io::{BufWriter, Write},
    path::PathBuf,
    time::Instant,
};

const PACKET_SIZES: [usize; 5] = [64, 256, 512, 1024, 1360];
const BATCH_SIZES: [usize; 4] = [1, 4, 16, 64];
const FLOW_COUNTS: [usize; 2] = [1, 4];
const REPEATS: usize = 5;
const TARGET_PACKETS_PER_REPEAT: usize = 65_536;

fn packet_payload(packet_size: usize, flow: usize) -> Vec<u8> {
    let mut packet = vec![0_u8; packet_size];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(packet_size as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    packet[20..22].copy_from_slice(&(20_000_u16 + flow as u16).to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[32] = 0x50;
    packet
}

fn packet_batch(packet_size: usize, batch_size: usize, flows: usize) -> PacketBatch {
    let mut batch = PacketBatch::with_capacity(batch_size);
    for index in 0..batch_size {
        let mut packet = ZCPacket::new_with_payload(&packet_payload(packet_size, index % flows));
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        batch.try_push(packet).unwrap();
    }
    batch
}

fn nonce(sequence: u64) -> Nonce {
    let mut bytes = [0_u8; 12];
    bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    Nonce::assume_unique_for_key(bytes)
}

fn median(mut values: Vec<u128>) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn measure(packet_size: usize, batch_size: usize, flows: usize) -> (usize, u128) {
    let iterations = (TARGET_PACKETS_PER_REPEAT / batch_size).max(256);
    let key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &[0x5a_u8; 32]).unwrap());
    let mut batch = packet_batch(packet_size, batch_size, flows);
    let mut crypto = (0..batch_size)
        .map(|_| packet_payload(packet_size, 0))
        .collect::<Vec<_>>();
    let mut sequence = 1_u64;
    let mut samples = Vec::with_capacity(REPEATS);
    for _ in 0..REPEATS {
        for packet in batch.iter_mut() {
            let last = packet.payload_len() - 1;
            packet.mut_payload()[last] ^= 1;
        }
        batch = benchmark_prepare_packet_batch(batch);
        let started = Instant::now();
        for _ in 0..iterations {
            batch = benchmark_prepare_packet_batch(batch);
            for buffer in &mut crypto {
                let _ = black_box(
                    key.seal_in_place_separate_tag(nonce(sequence), Aad::empty(), buffer)
                        .unwrap(),
                );
                sequence = sequence.wrapping_add(1);
            }
            black_box(&batch);
            for packet in batch.iter_mut() {
                let last = packet.payload_len() - 1;
                packet.mut_payload()[last] ^= 1;
            }
            for buffer in &mut crypto {
                buffer.fill(0xa5);
            }
        }
        let gross = started.elapsed().as_nanos();
        let control_started = Instant::now();
        for _ in 0..iterations {
            for packet in batch.iter_mut() {
                let last = packet.payload_len() - 1;
                packet.mut_payload()[last] ^= 1;
            }
            for buffer in &mut crypto {
                buffer.fill(0xa5);
            }
            black_box(&batch);
        }
        samples.push(gross.saturating_sub(control_started.elapsed().as_nanos()));
    }
    (iterations, median(samples))
}

#[test]
#[ignore = "release-mode performance model sweep"]
fn dataplane_cost_sweep() {
    let output = PathBuf::from(std::env::var_os("LOWTIER_COST_SWEEP_OUTPUT").unwrap());
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut output = BufWriter::new(File::create(output).unwrap());
    writeln!(
        output,
        "packet_size\tbatch_size\tflows\titerations\ttotal_ns\tns_per_packet"
    )
    .unwrap();
    for flows in FLOW_COUNTS {
        for packet_size in PACKET_SIZES {
            for batch_size in BATCH_SIZES {
                let (iterations, total_ns) = measure(packet_size, batch_size, flows);
                let packets = iterations * batch_size;
                writeln!(
                    output,
                    "{packet_size}\t{batch_size}\t{flows}\t{iterations}\t{total_ns}\t{:.6}",
                    total_ns as f64 / packets as f64
                )
                .unwrap();
            }
        }
    }
    output.flush().unwrap();
}
