use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use everscale_crypto::ed25519;
use old_rand::distributions::Distribution;
use ton_block::{Deserializable, Serializable};

pub fn mine(
    tvc: impl AsRef<Path>,
    abi: impl AsRef<Path>,
    field: &str,
    init_data: &str,
    pubkey: ed25519::PublicKey,
    target: ton_block::MsgAddressInt,
) -> Result<()> {
    let tvc = ton_block::StateInit::construct_from_file(tvc).context("Failed to read TVC")?;
    let abi = {
        let file = std::fs::File::open(abi).context("Failed to open ABI")?;
        ton_abi::Contract::load(std::io::BufReader::new(file)).context("Failed to read ABI")?
    };
    let init_data_params = abi
        .data()
        .values()
        .filter_map(|data| {
            if data.value.name != field {
                Some(data.value.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let field = abi.data().get(field).with_context(|| {
        format!(
            "Static field not found. Available: {}",
            abi.data()
                .keys()
                .map(|key| format!("'{}'", key))
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;

    let nonce_bits = match field.value.kind {
        ton_abi::ParamType::Uint(len) => len as u64,
        _ => return Err(anyhow::anyhow!("Nonce field must have type `uint256`")),
    };

    let mut init_data =
        serde_json::from_str::<serde_json::Value>(init_data).context("Invalid init data")?;
    if let serde_json::Value::Object(value) = &mut init_data {
        value.remove(&field.value.name);
    }

    let init_data = nekoton_abi::parse_abi_tokens(&init_data_params, init_data)
        .context("Failed to parse init data")?;

    let abi_version = *abi.version();

    let original_data = abi
        .update_data(
            tvc.data.clone().context("TVC doesn't have data")?.into(),
            &init_data,
        )
        .context("Failed to update init data")?;

    let original_data = ton_abi::Contract::insert_pubkey(original_data, pubkey.as_bytes())
        .context("Failed to update pubkey")?;

    let global_max_affinity = Arc::new(AtomicU8::new(0));

    let mut threads = Vec::new();

    let thread_count = std::thread::available_parallelism()
        .context("Failed to get available parallelism")?
        .get();

    for _ in 0..thread_count {
        let mut tvc = tvc.clone();

        let nonce_key: ton_types::SliceData = field.key.serialize()?.into();
        let mut original_data =
            ton_types::HashmapE::with_hashmap(64, original_data.reference_opt(0));

        let workchain = target.workchain_id();
        let target = target.address().get_bytestring(0);

        let global_max_affinity = global_max_affinity.clone();

        threads.push(std::thread::spawn(move || -> anyhow::Result<()> {
            let mut rng = old_rand::thread_rng();

            let distribution = num_bigint::RandomBits::new(nonce_bits);

            let mut max_affinity = 0;

            loop {
                let nonce: num_bigint::BigUint = distribution.sample(&mut rng);

                original_data
                    .set_builder(
                        nonce_key.clone(),
                        &ton_abi::TokenValue::Uint(ton_abi::Uint {
                            number: nonce.clone(),
                            size: nonce_bits as usize,
                        })
                        .pack_into_chain(&abi_version)?,
                    )
                    .context("Failed to update nonce")?;

                tvc.data = Some(
                    original_data
                        .serialize()
                        .context("Failed to serialize data")?,
                );

                let address = tvc
                    .serialize()
                    .context("Failed to serialize TVC")?
                    .repr_hash();

                let same_bits = affinity(address.as_slice(), &target);
                if same_bits <= max_affinity {
                    continue;
                }
                max_affinity = same_bits;

                if global_max_affinity.fetch_max(same_bits, Ordering::SeqCst) == max_affinity {
                    println!(
                        "Found new address ({} bits, nonce: 0x{}): {}:{:x}",
                        same_bits,
                        nonce.to_str_radix(16),
                        workchain,
                        address
                    );
                }
            }
        }));
    }

    for thread in threads {
        thread
            .join()
            .expect("Failed to join thread")
            .context("Failed to mine address")?;
    }

    Ok(())
}

pub fn affinity(left: &[u8], right: &[u8]) -> u8 {
    let len = std::cmp::min(left.len(), right.len());

    let mut result = 0;
    for i in 0..len {
        let x = left[i] ^ right[i];

        if x == 0 {
            result += 8;
        } else {
            if (x & 0xf0) == 0 {
                result += BITS[(x & 0x0f) as usize] + 4;
            } else {
                result += BITS[(x >> 4) as usize];
            }
            break;
        }
    }
    result
}

static BITS: [u8; 16] = [4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
