use clap::{Parser, Subcommand};
use orisyvra_core::{permute_rounds, ROUNDS, STATE_WORDS};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

#[derive(Parser, Debug)]
#[command(name = "orisyvra-analysis", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Measure one-bit diffusion over reduced rounds.
    Diffusion {
        #[arg(long, default_value_t = 4096)]
        samples: u64,
        #[arg(long, default_value_t = 0x4f72_4973_7956_7261)]
        seed: u64,
        #[arg(long, default_value_t = 1)]
        from_round: usize,
        #[arg(long, default_value_t = ROUNDS)]
        to_round: usize,
    },
    /// Measure output Hamming weight for a chosen input difference.
    Differential {
        #[arg(long)]
        rounds: usize,
        #[arg(long, default_value_t = 100_000)]
        samples: u64,
        #[arg(long, default_value_t = 0x4469_6666_6572_656e)]
        seed: u64,
        #[arg(long, default_value_t = 0)]
        word: usize,
        #[arg(long, default_value_t = 0)]
        bit: u32,
    },
    /// Search sampled states for fixed points and two-cycles.
    ShortCycles {
        #[arg(long)]
        rounds: usize,
        #[arg(long, default_value_t = 1_000_000)]
        samples: u64,
        #[arg(long, default_value_t = 0x4379_636c_6553_6565)]
        seed: u64,
    },
}

#[derive(Clone, Copy, Debug, Default)]
struct Stats {
    count: u64,
    total: u128,
    minimum: u32,
    maximum: u32,
}

impl Stats {
    fn push(&mut self, value: u32) {
        if self.count == 0 {
            self.minimum = value;
            self.maximum = value;
        } else {
            self.minimum = self.minimum.min(value);
            self.maximum = self.maximum.max(value);
        }
        self.count += 1;
        self.total += value as u128;
    }
    fn mean(self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total as f64 / self.count as f64
        }
    }
}

fn random_state(rng: &mut StdRng) -> [u64; STATE_WORDS] {
    core::array::from_fn(|_| rng.next_u64())
}
fn hamming(left: &[u64], right: &[u64]) -> u32 {
    left.iter()
        .zip(right)
        .map(|(a, b)| (a ^ b).count_ones())
        .sum()
}
fn validate_rounds(rounds: usize) {
    assert!(
        (1..=ROUNDS).contains(&rounds),
        "rounds must be 1..={ROUNDS}"
    );
}

fn diffusion(samples: u64, seed: u64, from_round: usize, to_round: usize) {
    validate_rounds(from_round);
    validate_rounds(to_round);
    assert!(
        from_round <= to_round,
        "from-round must not exceed to-round"
    );
    println!("rounds,samples,mean_bits,min_bits,max_bits,mean_collision,mean_wave");
    for rounds in from_round..=to_round {
        let mut rng = StdRng::seed_from_u64(seed ^ rounds as u64);
        let mut all = Stats::default();
        let mut collision = Stats::default();
        let mut wave = Stats::default();
        for sample in 0..samples {
            let mut left = random_state(&mut rng);
            let mut right = left;
            let bit = ((rng.next_u64() ^ sample) % 768) as usize;
            right[bit / 64] ^= 1_u64 << (bit % 64);
            permute_rounds(&mut left, rounds);
            permute_rounds(&mut right, rounds);
            all.push(hamming(&left, &right));
            collision.push(hamming(&left[..6], &right[..6]));
            wave.push(hamming(&left[6..], &right[6..]));
        }
        println!(
            "{rounds},{},{:.6},{},{},{:.6},{:.6}",
            all.count,
            all.mean(),
            all.minimum,
            all.maximum,
            collision.mean(),
            wave.mean()
        );
    }
}

fn differential(rounds: usize, samples: u64, seed: u64, word: usize, bit: u32) {
    validate_rounds(rounds);
    assert!(word < STATE_WORDS, "word out of range");
    assert!(bit < 64, "bit must be 0..63");
    let mut rng = StdRng::seed_from_u64(seed);
    let mut all = Stats::default();
    let mut collision = Stats::default();
    let mut wave = Stats::default();
    for _ in 0..samples {
        let mut left = random_state(&mut rng);
        let mut right = left;
        right[word] ^= 1_u64 << bit;
        permute_rounds(&mut left, rounds);
        permute_rounds(&mut right, rounds);
        all.push(hamming(&left, &right));
        collision.push(hamming(&left[..6], &right[..6]));
        wave.push(hamming(&left[6..], &right[6..]));
    }
    println!("rounds={rounds}");
    println!("samples={}", all.count);
    println!("difference=word:{word},bit:{bit}");
    println!("mean_bits={:.6}", all.mean());
    println!("min_bits={}", all.minimum);
    println!("max_bits={}", all.maximum);
    println!("mean_collision={:.6}", collision.mean());
    println!("mean_wave={:.6}", wave.mean());
}

fn short_cycles(rounds: usize, samples: u64, seed: u64) {
    validate_rounds(rounds);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut fixed = 0_u64;
    let mut two_cycles = 0_u64;
    for _ in 0..samples {
        let original = random_state(&mut rng);
        let mut once = original;
        permute_rounds(&mut once, rounds);
        if once == original {
            fixed += 1;
            continue;
        }
        let mut twice = once;
        permute_rounds(&mut twice, rounds);
        if twice == original {
            two_cycles += 1;
        }
    }
    println!("rounds={rounds}");
    println!("samples={samples}");
    println!("fixed_points={fixed}");
    println!("two_cycles={two_cycles}");
}

fn main() {
    match Cli::parse().command {
        Command::Diffusion {
            samples,
            seed,
            from_round,
            to_round,
        } => diffusion(samples, seed, from_round, to_round),
        Command::Differential {
            rounds,
            samples,
            seed,
            word,
            bit,
        } => differential(rounds, samples, seed, word, bit),
        Command::ShortCycles {
            rounds,
            samples,
            seed,
        } => short_cycles(rounds, samples, seed),
    }
}
