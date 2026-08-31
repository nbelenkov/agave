//! A branchy, total function for the platform's CI test target.
//!
//! It must do two things and nothing else: gain coverage as inputs vary (so the platform's
//! bad-build guard, which fails a binary that never reports `cov:`, sees a working fuzzer), and
//! never crash. A crashing test target would open real Tracecat cases and file artifacts in the
//! crashes bucket on every CI run — noise indistinguishable from a finding.
pub fn classify(data: &[u8]) -> u32 {
    let mut score = 0u32;
    for (i, b) in data.iter().enumerate().take(64) {
        // Nested branches give the fuzzer edges to discover, none of them reachable only by a bug.
        if b % 3 == 0 {
            score = score.wrapping_add(1);
        } else if b % 5 == 0 {
            score = score.wrapping_add(2);
        }
        if i > 0 && data[i - 1] == *b {
            score = score.wrapping_mul(3);
        }
    }
    match data.first() {
        Some(0xAA) => score.wrapping_add(7),
        Some(0xBB) if data.len() > 8 => score.wrapping_add(11),
        _ => score,
    }
}
