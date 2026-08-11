use byteorder::{BigEndian, ByteOrder};

/// A pure Rust scalar (non-SIMD) implementation for the checksum accumulation.
///
/// It uses a simple loop instead of manual unrolling for better clarity and maintainability.
fn checksum_no_fold_scalar(mut b: &[u8], initial: u64) -> u64 {
    let mut accumulator = initial;

    while b.len() >= 4 {
        accumulator += BigEndian::read_u32(&b[0..4]) as u64;
        b = &b[4..];
    }

    if b.len() >= 2 {
        accumulator += BigEndian::read_u16(&b[0..2]) as u64;
        b = &b[2..];
    }

    if let Some(&byte) = b.first() {
        // Odd byte is treated as the high byte of a 16-bit word (RFC 1071).
        accumulator += (byte as u64) << 8;
    }

    accumulator
}

/// A SIMD-accelerated (AVX2) implementation for the checksum accumulation.
///
/// # Safety
/// Caller must ensure this function is called only on CPUs that support AVX2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn checksum_no_fold_avx2(mut b: &[u8], initial: u64) -> u64 {
    unsafe {
        use std::arch::x86_64::*;

        let mut accumulator = initial;
        const CHUNK_SIZE: usize = 32;

        if b.len() >= CHUNK_SIZE {
            let mut sums = _mm256_setzero_si256();

            // Network payloads are big-endian; shuffle so 32-bit lanes widen natively.
            let shuffle_mask = _mm256_set_epi8(
                12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11,
                4, 5, 6, 7, 0, 1, 2, 3,
            );

            while b.len() >= CHUNK_SIZE {
                let data = _mm256_loadu_si256(b.as_ptr() as *const __m256i);
                let swapped = _mm256_shuffle_epi8(data, shuffle_mask);

                let lower_u64 = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(swapped, 0));
                sums = _mm256_add_epi64(sums, lower_u64);

                let upper_u64 = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(swapped, 1));
                sums = _mm256_add_epi64(sums, upper_u64);

                b = &b[CHUNK_SIZE..];
            }

            accumulator += _mm256_extract_epi64(sums, 0) as u64;
            accumulator += _mm256_extract_epi64(sums, 1) as u64;
            accumulator += _mm256_extract_epi64(sums, 2) as u64;
            accumulator += _mm256_extract_epi64(sums, 3) as u64;
        }

        checksum_no_fold_scalar(b, accumulator)
    }
}

/// A SIMD-accelerated (SSE4.1) implementation for the checksum accumulation.
///
/// # Safety
/// Caller must ensure this function is called only on CPUs that support SSE4.1.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1")]
unsafe fn checksum_no_fold_sse41(mut b: &[u8], initial: u64) -> u64 {
    unsafe {
        use std::arch::x86_64::*;

        let mut accumulator = initial;
        const CHUNK_SIZE: usize = 16;

        if b.len() >= CHUNK_SIZE {
            let mut sums = _mm_setzero_si128();

            // Network payloads are big-endian; shuffle so 32-bit lanes widen natively.
            let shuffle_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

            while b.len() >= CHUNK_SIZE {
                let data = _mm_loadu_si128(b.as_ptr() as *const __m128i);
                let swapped = _mm_shuffle_epi8(data, shuffle_mask);

                let lower_u64 = _mm_cvtepu32_epi64(swapped);
                sums = _mm_add_epi64(sums, lower_u64);

                let upper_u64 = _mm_cvtepu32_epi64(_mm_bsrli_si128(swapped, 8));
                sums = _mm_add_epi64(sums, upper_u64);

                b = &b[CHUNK_SIZE..];
            }

            accumulator += _mm_cvtsi128_si64(sums) as u64;
            accumulator += _mm_extract_epi64(sums, 1) as u64;
        }

        checksum_no_fold_scalar(b, accumulator)
    }
}

/// Accumulate network-order words with the AArch64 NEON unit.
///
/// # Safety
/// AArch64 always provides NEON support.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn checksum_no_fold_neon(mut b: &[u8], initial: u64) -> u64 {
    unsafe {
        use std::arch::aarch64::*;

        const CHUNK_SIZE: usize = 16;
        let mut sums = vdupq_n_u64(0);

        while b.len() >= CHUNK_SIZE {
            let bytes = vld1q_u8(b.as_ptr());
            let words = vreinterpretq_u32_u8(vrev32q_u8(bytes));
            sums = vaddq_u64(sums, vmovl_u32(vget_low_u32(words)));
            sums = vaddq_u64(sums, vmovl_high_u32(words));
            b = &b[CHUNK_SIZE..];
        }

        let accumulator = initial + vgetq_lane_u64(sums, 0) + vgetq_lane_u64(sums, 1);
        checksum_no_fold_scalar(b, accumulator)
    }
}

/// RFC 1071 checksum accumulator over `b`, without folding to 16 bits.
///
/// Treats the input as big-endian `u32` chunks and accumulates in `u64` to avoid
/// overflow. Dispatches to SIMD where supported.
#[inline]
pub fn checksum_no_fold(b: &[u8], initial: u64) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: We have just checked that the CPU supports AVX2.
            return unsafe { checksum_no_fold_avx2(b, initial) };
        }
        if is_x86_feature_detected!("sse4.1") {
            // SAFETY: We have just checked that the CPU supports SSE4.1.
            return unsafe { checksum_no_fold_sse41(b, initial) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: AArch64 includes the NEON instruction set.
        return unsafe { checksum_no_fold_neon(b, initial) };
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        checksum_no_fold_scalar(b, initial)
    }

    #[cfg(target_arch = "x86_64")]
    {
        checksum_no_fold_scalar(b, initial)
    }
}

/// Returns the final 16-bit RFC 1071 internet checksum.
pub fn checksum(b: &[u8], initial: u64) -> u16 {
    let mut accumulator = checksum_no_fold(b, initial);

    while accumulator > 0xFFFF {
        accumulator = (accumulator >> 16) + (accumulator & 0xFFFF);
    }

    accumulator as u16
}

/// RFC 1071 checksum accumulator over a TCP/UDP pseudo-header.
pub fn pseudo_header_checksum_no_fold(
    protocol: u8,
    src_addr: &[u8],
    dst_addr: &[u8],
    total_len: u16,
) -> u64 {
    let sum = checksum_no_fold(src_addr, 0);
    let sum = checksum_no_fold(dst_addr, sum);

    // Pseudo-header trailer is {zero, protocol, total_len}.
    let len_bytes = total_len.to_be_bytes();
    let trailer = [0, protocol, len_bytes[0], len_bytes[1]];
    checksum_no_fold(&trailer, sum)
}

#[cfg(test)]
mod tests {
    use crate::platform::linux::checksum::checksum_no_fold_scalar;

    fn deterministic_data(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| index.wrapping_mul(37).wrapping_add(11) as u8)
            .collect()
    }

    #[test]
    fn scalar_checksum_handles_all_tail_lengths() {
        let lengths = [0, 1, 2, 3, 4, 15, 16, 17, 63, 64, 65, 1500, 65535];
        for length in lengths {
            let data = deterministic_data(length);
            let mut expected = data
                .chunks(2)
                .map(|word| match word {
                    [high, low] => u16::from_be_bytes([*high, *low]) as u64,
                    [high] => (*high as u64) << 8,
                    _ => 0,
                })
                .sum::<u64>();
            while expected > 0xffff {
                expected = (expected >> 16) + (expected & 0xffff);
            }
            let mut actual = checksum_no_fold_scalar(&data, 0);
            while actual > 0xffff {
                actual = (actual >> 16) + (actual & 0xffff);
            }
            assert_eq!(actual, expected);
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn neon_checksum_matches_scalar_for_packet_boundaries() {
        use crate::platform::linux::checksum::checksum_no_fold_neon;

        let lengths = [0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 1500, 9000, 65535];
        let initial_values = [0_u64, 1, 12345, u32::MAX as u64];
        for length in lengths {
            let data = deterministic_data(length);
            for initial in initial_values {
                let expected = checksum_no_fold_scalar(&data, initial);
                let actual = unsafe { checksum_no_fold_neon(&data, initial) };
                assert_eq!(actual, expected, "length {length}, initial {initial}");
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    use crate::platform::linux::checksum::{checksum_no_fold_avx2, checksum_no_fold_sse41};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_checksum_avx2_vs_scalar_output() {
        // Only run this test on x86/x64 architectures if AVX2 feature is detected
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if !is_x86_feature_detected!("avx2") {
            println!("AVX2 feature not detected. Skipping AVX2 checksum output comparison tests.");
            return;
        }

        // Initialize deterministic data (no rand dependency needed)

        // Test data lengths, including boundary cases and lengths larger than CHUNK_SIZE
        let test_lengths = [31, 32, 33, 63, 64, 65, 100, 1024, 4096];
        // Different initial accumulator values
        let initial_values = [0u64, 1u64, 12345u64];

        println!(
            "\n--- Comparing checksum_no_fold_avx2 output with checksum_no_fold_scalar output ---"
        );
        println!("Note: These two functions perform different types of summations (u32 vs u8).");
        println!(
            "If this test fails, it's likely due to this fundamental difference in calculation logic,"
        );
        println!(
            "not necessarily an 'error' in implementation, but a mismatch in expected behavior."
        );

        for &len in &test_lengths {
            for &initial in &initial_values {
                // Generate deterministic data
                let mut data = vec![0u8; len];
                for (i, b) in data.iter_mut().enumerate() {
                    *b = (i % 256) as u8;
                }

                // Calculate the expected value using the scalar benchmark function
                let expected = checksum_no_fold_scalar(&data, initial);
                if is_x86_feature_detected!("avx2") {
                    // Calculate the actual value using the AVX2 function
                    // SAFETY: `is_x86_feature_detected!("avx2")` confirms CPU support.
                    let actual = unsafe { checksum_no_fold_avx2(&data, initial) };

                    // Assert that the results are equal
                    assert_eq!(
                        actual, expected,
                        "Output Mismatch! Length: {len}, Initial: {initial}, Data: {data:?}\nAVX2 Result: {actual}\nScalar Result: {expected}",
                    );
                }
                if is_x86_feature_detected!("sse4.1") {
                    // SAFETY: `is_x86_feature_detected!("sse4.1")` confirms CPU support.
                    let actual = unsafe { checksum_no_fold_sse41(&data, initial) };

                    // Assert that the results are equal
                    assert_eq!(
                        actual, expected,
                        "Output Mismatch! Length: {len}, Initial: {initial}, Data: {data:?}\nsse41 Result: {actual}\nScalar Result: {expected}",
                    );
                }
            }
        }
        println!(
            "\nAll output comparison tests passed (assuming expected mismatch is handled by design)."
        );
    }
}
