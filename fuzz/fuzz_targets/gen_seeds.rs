//! Writes real shred payloads into the `shred_layout` and `shred_parse` corpora.
//! Usage: cargo run --release --bin gen_seeds -- [corpus_root, default corpus/]

use {
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_ledger::shred::{ProcessShredsStats, Shred, Shredder},
    std::{env, fs, path::PathBuf},
};

fn main() {
    let root = PathBuf::from(env::args().nth(1).unwrap_or_else(|| "corpus".to_string()));
    let keypair = Keypair::new_from_array([7u8; 32]);

    let mut payloads: Vec<Vec<u8>> = Vec::new();
    for data_len in [0usize, 1, 200, 1500, 30_000, 200_000] {
        for is_last_in_slot in [false, true] {
            let data = vec![0xa5u8; data_len];
            let shredder = Shredder::new(100, 99, 0, 0).expect("valid shredder params");
            let mut stats = ProcessShredsStats::default();
            let Ok(shreds) = shredder.make_shreds_from_data_slice(
                &keypair,
                &data,
                is_last_in_slot,
                Hash::default(),
                0,
                0,
                &mut stats,
            ) else {
                continue;
            };
            for shred in shreds {
                payloads.push(shred.payload().to_vec());
            }
        }
    }

    for p in &payloads {
        Shred::new_from_serialized_shred(p.clone())
            .expect("generated seed must parse against current shred format");
    }

    let mut written = 0usize;
    for target in ["shred_layout", "shred_parse"] {
        let dir = root.join(target);
        fs::create_dir_all(&dir).expect("create corpus dir");
        for (i, payload) in payloads.iter().enumerate() {
            let path = dir.join(format!("seed_{i:04}.bin"));
            fs::write(&path, payload).expect("write seed");
            written += 1;
        }
    }

    println!(
        "wrote {written} seed files ({} unique payloads) under {}",
        payloads.len(),
        root.display()
    );
}
