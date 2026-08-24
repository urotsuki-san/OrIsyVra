use crate::constants::{RC_A, RC_B, RC_C};

pub const STATE_WORDS: usize = 12;
pub const STATE_BYTES: usize = STATE_WORDS * 8;
pub const RATE_WORDS: usize = 6;
pub const RATE_BYTES: usize = RATE_WORDS * 8;
pub const CAPACITY_BYTES: usize = STATE_BYTES - RATE_BYTES;
pub const ROUNDS: usize = 18;

const PAIRINGS: [[[usize; 2]; 3]; 3] = [
    [[0, 1], [2, 3], [4, 5]],
    [[0, 2], [1, 4], [3, 5]],
    [[0, 3], [1, 5], [2, 4]],
];

const C_PERM: [[usize; 6]; 3] = [[1, 4, 2, 5, 0, 3], [2, 0, 5, 3, 1, 4], [3, 5, 1, 0, 4, 2]];
const W_PERM: [[usize; 6]; 3] = [[5, 2, 0, 4, 1, 3], [4, 1, 3, 0, 5, 2], [2, 5, 1, 4, 0, 3]];

const C_ROT: [u32; 6] = [7, 17, 29, 37, 47, 59];
const W_ROT: [u32; 6] = [11, 23, 31, 41, 53, 61];
const WAVE_LEFT_ROT: [u32; 6] = [5, 13, 19, 31, 43, 57];
const WAVE_RIGHT_ROT: [u32; 6] = [3, 11, 27, 35, 49, 63];
const KICK_C_ROT: [u32; 6] = [9, 21, 33, 45, 55, 15];
const KICK_W_ROT: [u32; 6] = [7, 25, 39, 51, 17, 29];

#[inline(always)]
fn round_rot(base: u32, round: usize, lane: usize, stride: usize) -> u32 {
    (((base as usize + round * stride + lane * 5) % 63) + 1) as u32
}

#[inline(always)]
fn collide_forward(
    lanes: &mut [u64; 6],
    a_index: usize,
    b_index: usize,
    round: usize,
    pair: usize,
) {
    let mut a = lanes[a_index];
    let mut b = lanes[b_index];
    let r1 = round_rot(7, round, pair, 7);
    let r2 = round_rot(19, round, pair, 11);
    let r3 = round_rot(31, round, pair, 13);
    a = a.wrapping_add(b.rotate_left(r1));
    b ^= a.rotate_left(r2);
    a = a.rotate_left(r3);
    lanes[a_index] = a;
    lanes[b_index] = b;
}

#[inline(always)]
fn collide_inverse(
    lanes: &mut [u64; 6],
    a_index: usize,
    b_index: usize,
    round: usize,
    pair: usize,
) {
    let mut a = lanes[a_index];
    let mut b = lanes[b_index];
    let r1 = round_rot(7, round, pair, 7);
    let r2 = round_rot(19, round, pair, 11);
    let r3 = round_rot(31, round, pair, 13);
    a = a.rotate_right(r3);
    b ^= a.rotate_left(r2);
    a = a.wrapping_sub(b.rotate_left(r1));
    lanes[a_index] = a;
    lanes[b_index] = b;
}

#[inline(always)]
fn permute_words(lanes: &mut [u64; 6], permutation: &[usize; 6]) {
    let previous = *lanes;
    for output in 0..6 {
        lanes[output] = previous[permutation[output]];
    }
}

#[inline(always)]
fn inverse_permute_words(lanes: &mut [u64; 6], permutation: &[usize; 6]) {
    let previous = *lanes;
    for output in 0..6 {
        lanes[permutation[output]] = previous[output];
    }
}

#[inline(always)]
fn split_state(state: &[u64; STATE_WORDS]) -> ([u64; 6], [u64; 6]) {
    let mut collision = [0_u64; 6];
    let mut wave = [0_u64; 6];
    collision.copy_from_slice(&state[..6]);
    wave.copy_from_slice(&state[6..]);
    (collision, wave)
}

#[inline(always)]
fn join_state(state: &mut [u64; STATE_WORDS], collision: &[u64; 6], wave: &[u64; 6]) {
    state[..6].copy_from_slice(collision);
    state[6..].copy_from_slice(wave);
}

#[inline(always)]
fn round_forward(state: &mut [u64; STATE_WORDS], round: usize) {
    let (mut collision, mut wave) = split_state(state);
    let schedule = round % 3;
    collision[0] ^= RC_A[round];
    wave[5] ^= RC_B[round];
    collision[3] = collision[3].wrapping_add(RC_C[round]);

    for (pair_index, pair) in PAIRINGS[schedule].iter().enumerate() {
        collide_forward(&mut collision, pair[0], pair[1], round, pair_index);
    }
    for lane in 0..6 {
        let left = wave[(lane + 5) % 6].rotate_left(WAVE_LEFT_ROT[lane]);
        let right = wave[(lane + 1) % 6].rotate_left(WAVE_RIGHT_ROT[lane]);
        wave[lane] = wave[lane].wrapping_add(left ^ right);
    }
    for lane in 0..6 {
        collision[lane] ^= wave[(lane + round + 1) % 6].rotate_left(KICK_C_ROT[lane]);
    }
    for lane in 0..6 {
        let impulse = collision[(lane + 2) % 6] ^ collision[(lane + 5) % 6];
        wave[lane] = wave[lane].wrapping_add(impulse.rotate_left(KICK_W_ROT[lane]));
    }
    for lane in 0..6 {
        collision[lane] = collision[lane].rotate_left(round_rot(C_ROT[lane], round, lane, 3));
        wave[lane] = wave[lane].rotate_left(round_rot(W_ROT[lane], round, lane, 5));
    }
    permute_words(&mut collision, &C_PERM[schedule]);
    permute_words(&mut wave, &W_PERM[schedule]);
    join_state(state, &collision, &wave);
}

#[inline(always)]
fn round_inverse(state: &mut [u64; STATE_WORDS], round: usize) {
    let (mut collision, mut wave) = split_state(state);
    let schedule = round % 3;
    inverse_permute_words(&mut collision, &C_PERM[schedule]);
    inverse_permute_words(&mut wave, &W_PERM[schedule]);
    for lane in 0..6 {
        collision[lane] = collision[lane].rotate_right(round_rot(C_ROT[lane], round, lane, 3));
        wave[lane] = wave[lane].rotate_right(round_rot(W_ROT[lane], round, lane, 5));
    }
    for lane in (0..6).rev() {
        let impulse = collision[(lane + 2) % 6] ^ collision[(lane + 5) % 6];
        wave[lane] = wave[lane].wrapping_sub(impulse.rotate_left(KICK_W_ROT[lane]));
    }
    for lane in (0..6).rev() {
        collision[lane] ^= wave[(lane + round + 1) % 6].rotate_left(KICK_C_ROT[lane]);
    }
    for lane in (0..6).rev() {
        let left = wave[(lane + 5) % 6].rotate_left(WAVE_LEFT_ROT[lane]);
        let right = wave[(lane + 1) % 6].rotate_left(WAVE_RIGHT_ROT[lane]);
        wave[lane] = wave[lane].wrapping_sub(left ^ right);
    }
    for (pair_index, pair) in PAIRINGS[schedule].iter().enumerate().rev() {
        collide_inverse(&mut collision, pair[0], pair[1], round, pair_index);
    }
    collision[3] = collision[3].wrapping_sub(RC_C[round]);
    wave[5] ^= RC_B[round];
    collision[0] ^= RC_A[round];
    join_state(state, &collision, &wave);
}

/// Apply the full permutation.
pub fn permute(state: &mut [u64; STATE_WORDS]) {
    for round in 0..ROUNDS {
        round_forward(state, round);
    }
}

/// Apply the inverse permutation.
pub fn invert(state: &mut [u64; STATE_WORDS]) {
    for round in (0..ROUNDS).rev() {
        round_inverse(state, round);
    }
}

#[cfg(feature = "analysis")]
pub fn permute_rounds(state: &mut [u64; STATE_WORDS], rounds: usize) {
    assert!(rounds <= ROUNDS, "round count exceeds full permutation");
    for round in 0..rounds {
        round_forward(state, round);
    }
}

#[cfg(feature = "analysis")]
pub fn invert_rounds(state: &mut [u64; STATE_WORDS], rounds: usize) {
    assert!(rounds <= ROUNDS, "round count exceeds full permutation");
    for round in (0..rounds).rev() {
        round_inverse(state, round);
    }
}

#[cfg(test)]
mod tests {
    use super::{invert, permute, STATE_WORDS};

    #[test]
    fn permutation_is_invertible() {
        let mut seed = 0x6f72_6973_7976_7261_u64;
        for case in 0..128_u64 {
            let mut state = [0_u64; STATE_WORDS];
            for (lane, word) in state.iter_mut().enumerate() {
                seed = seed
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .wrapping_add(case ^ lane as u64);
                *word = seed ^ seed.rotate_left((lane * 7) as u32);
            }
            let original = state;
            permute(&mut state);
            assert_ne!(state, original);
            invert(&mut state);
            assert_eq!(state, original);
        }
    }
}
