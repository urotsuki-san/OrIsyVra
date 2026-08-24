use crate::constants::IV;
use crate::permutation::{permute, RATE_BYTES, RATE_WORDS, STATE_WORDS};

pub const KEY_SIZE: usize = 48;
pub const TAG_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum Domain {
    KeyDerivation = 0x4f59_562d_4b44_4631,
    HeaderBinding = 0x4f59_562d_4844_5231,
    RecordSiv = 0x4f59_562d_5349_5631,
    Stream = 0x4f59_562d_5354_5231,
    Manifest = 0x4f59_562d_4d41_4e31,
    RandomGenerator = 0x4f59_562d_524e_4731,
}

struct KeyedSponge {
    state: [u64; STATE_WORDS],
    buffer: [u8; RATE_BYTES],
    position: usize,
    absorbed: u64,
}

impl KeyedSponge {
    fn new(key: &[u8; KEY_SIZE], domain: Domain) -> Self {
        let mut state = IV;
        for lane in 0..RATE_WORDS {
            let start = lane * 8;
            let key_word =
                u64::from_le_bytes(key[start..start + 8].try_into().expect("fixed key lane"));
            state[lane] =
                state[lane].wrapping_add(key_word.rotate_left(((lane * 9 + 7) % 64) as u32));
            state[RATE_WORDS + lane] ^= key_word;
        }
        state[0] ^= domain as u64;
        state[STATE_WORDS - 1] ^= (KEY_SIZE as u64) << 32;
        permute(&mut state);
        Self {
            state,
            buffer: [0; RATE_BYTES],
            position: 0,
            absorbed: 0,
        }
    }

    fn absorb(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            let take = (RATE_BYTES - self.position).min(input.len());
            self.buffer[self.position..self.position + take].copy_from_slice(&input[..take]);
            self.position += take;
            self.absorbed = self.absorbed.wrapping_add(take as u64);
            input = &input[take..];
            if self.position == RATE_BYTES {
                self.commit_block();
            }
        }
    }

    fn commit_block(&mut self) {
        for lane in 0..RATE_WORDS {
            let start = lane * 8;
            let word = u64::from_le_bytes(
                self.buffer[start..start + 8]
                    .try_into()
                    .expect("fixed rate lane"),
            );
            self.state[lane] ^= word;
        }
        permute(&mut self.state);
        self.buffer.fill(0);
        self.position = 0;
    }

    fn finalize(&mut self, key: &[u8; KEY_SIZE], output_length: usize) {
        self.buffer[self.position] ^= 0x01;
        self.buffer[RATE_BYTES - 1] ^= 0x80;
        self.commit_block();
        for lane in 0..RATE_WORDS {
            let start = lane * 8;
            let key_word =
                u64::from_le_bytes(key[start..start + 8].try_into().expect("fixed key lane"));
            self.state[RATE_WORDS + lane] ^= key_word;
        }
        self.state[0] ^= self.absorbed;
        self.state[1] ^= output_length as u64;
        self.state[STATE_WORDS - 1] ^= 0x8000_0000_0000_0001;
        permute(&mut self.state);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        let mut written = 0;
        let mut block_index = 0_u64;
        while written < output.len() {
            let mut block = [0_u8; RATE_BYTES];
            for lane in 0..RATE_WORDS {
                let start = lane * 8;
                block[start..start + 8].copy_from_slice(&self.state[lane].to_le_bytes());
            }
            let take = (output.len() - written).min(RATE_BYTES);
            output[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            if written < output.len() {
                block_index = block_index.wrapping_add(1);
                self.state[STATE_WORDS - 2] ^= block_index;
                self.state[STATE_WORDS - 1] =
                    self.state[STATE_WORDS - 1].wrapping_add(0x9e37_79b9_7f4a_7c15);
                permute(&mut self.state);
            }
        }
    }
}

/// Expand length-prefixed inputs under a domain-separated key.
pub fn prf_parts(key: &[u8; KEY_SIZE], domain: Domain, parts: &[&[u8]], output: &mut [u8]) {
    let mut sponge = KeyedSponge::new(key, domain);
    for part in parts {
        sponge.absorb(&(part.len() as u64).to_le_bytes());
        sponge.absorb(part);
    }
    sponge.finalize(key, output.len());
    sponge.squeeze(output);
}

pub fn derive_key(master_key: &[u8; KEY_SIZE], label: &[u8], context: &[u8]) -> [u8; KEY_SIZE] {
    let mut derived = [0_u8; KEY_SIZE];
    prf_parts(
        master_key,
        Domain::KeyDerivation,
        &[label, context],
        &mut derived,
    );
    derived
}

pub fn mac32(key: &[u8; KEY_SIZE], domain: Domain, parts: &[&[u8]]) -> [u8; TAG_SIZE] {
    let mut tag = [0_u8; TAG_SIZE];
    prf_parts(key, domain, parts, &mut tag);
    tag
}

#[cfg(test)]
mod tests {
    use super::{derive_key, mac32, prf_parts, Domain, KEY_SIZE};

    #[test]
    fn deterministic_and_domain_separated() {
        let key = [0x42_u8; KEY_SIZE];
        let mut a = [0_u8; 96];
        let mut b = [0_u8; 96];
        let mut c = [0_u8; 96];
        prf_parts(&key, Domain::Stream, &[b"same input"], &mut a);
        prf_parts(&key, Domain::Stream, &[b"same input"], &mut b);
        prf_parts(&key, Domain::RecordSiv, &[b"same input"], &mut c);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn part_boundaries_are_unambiguous() {
        let key = [0x19_u8; KEY_SIZE];
        assert_ne!(
            mac32(&key, Domain::RecordSiv, &[b"ab", b"c"]),
            mac32(&key, Domain::RecordSiv, &[b"a", b"bc"])
        );
    }

    #[test]
    fn derived_keys_change_with_label_and_context() {
        let key = [0xa5_u8; KEY_SIZE];
        assert_ne!(
            derive_key(&key, b"alpha", b"context"),
            derive_key(&key, b"beta", b"context")
        );
    }
}
