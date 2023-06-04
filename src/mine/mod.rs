use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use everscale_crypto::ed25519;
use nekoton_abi::BuildTokenValue;
use nekoton_utils::TrustMe;
use rand::distributions::Distribution;
use ton_block::{Deserializable, Serializable};
use ton_types::SliceData;

pub fn mine(
    tvc: impl AsRef<Path>,
    abi: impl AsRef<Path>,
    field: &str,
    init_data: &str,
    pubkey: ed25519::PublicKey,
    target: ton_block::MsgAddressInt,
    token_root: Option<ton_block::MsgAddressInt>,
) -> Result<()> {
    let bytes = std::fs::read(tvc)?;
    let tvc = ton_block::StateInit::construct_from_bytes(&bytes).context("Failed to read TVC")?;
    let abi = {
        let abi = std::fs::read_to_string(abi).context("Failed to open ABI")?;
        ton_abi::Contract::load(&abi).context("Failed to read ABI")?
    };
    let init_data_params = abi
        .data
        .values()
        .filter_map(|data| {
            if data.value.name != field {
                Some(data.value.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let field = abi.data.get(field).with_context(|| {
        format!(
            "Static field not found. Available: {}",
            abi.data
                .keys()
                .map(|key| format!("'{key}'"))
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

    let abi_version = abi.abi_version;

    let original_data = abi
        .update_data(
            tvc.data
                .clone()
                .context("TVC doesn't have data")
                .and_then(SliceData::load_cell)?,
            &init_data,
        )
        .context("Failed to update init data")?;

    let original_data = ton_abi::Contract::insert_pubkey(original_data, pubkey.as_bytes())
        .context("Failed to update pubkey")?;

    let token_state = token_root.map(TokenState::new);

    let global_max_affinity = Arc::new(AtomicU8::new(0));

    let mut threads = Vec::new();

    let thread_count = std::thread::available_parallelism()
        .context("Failed to get available parallelism")?
        .get();

    for _ in 0..thread_count {
        let mut tvc = tvc.clone();

        let nonce_key: ton_types::SliceData =
            field.key.serialize().and_then(SliceData::load_cell)?;
        let mut original_data =
            ton_types::HashmapE::with_hashmap(64, original_data.reference_opt(0));

        let workchain_id = target.workchain_id() as i8;
        let target = target.address().get_bytestring(0);
        let mut token_state = token_state.clone();

        let global_max_affinity = global_max_affinity.clone();

        threads.push(std::thread::spawn(move || -> Result<()> {
            let mut rng = rand::thread_rng();

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

                let mut address_affinity = affinity(address.as_slice(), &target);

                let token_wallet = if let Some(token_state) = &mut token_state {
                    let token_wallet = token_state.compute_address(address);

                    let token_address_affinity = affinity(token_wallet.as_slice(), &target);
                    address_affinity = std::cmp::min(address_affinity, token_address_affinity);

                    Some(token_wallet)
                } else {
                    None
                };

                if address_affinity <= max_affinity {
                    continue;
                }
                max_affinity = address_affinity;

                if global_max_affinity.fetch_max(address_affinity, Ordering::SeqCst) == max_affinity
                {
                    let token_address = token_wallet
                        .map(|addr| format!(" | Token: 0:{addr:x}"))
                        .unwrap_or_default();

                    println!(
                        "Bits: {} | Nonce: 0x{} | Address: {}:{:x}{}",
                        address_affinity,
                        nonce.to_str_radix(16),
                        workchain_id,
                        address,
                        token_address
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

#[derive(Clone)]
struct TokenState {
    state: ton_block::StateInit,
    data: ton_types::HashmapE,
}

impl TokenState {
    fn new(token_root: ton_block::MsgAddressInt) -> Self {
        let state = load_token_state();

        let mut data = ton_types::HashmapE::with_hashmap(
            64,
            state
                .data
                .as_ref()
                .expect("Always has been")
                .reference(0)
                .ok(),
        );

        let builder = token_root
            .token_value()
            .pack_into_chain(&ton_abi::contract::ABI_VERSION_2_2)
            .trust_me();

        data.set_builder(
            1u64.serialize().and_then(SliceData::load_cell).trust_me(),
            &builder,
        )
        .trust_me();

        Self { state, data }
    }

    fn compute_address(&mut self, address: ton_types::UInt256) -> ton_types::UInt256 {
        self.data
            .set_builder(
                2u64.serialize().and_then(SliceData::load_cell).trust_me(),
                &ton_abi::TokenValue::Address(ton_block::MsgAddress::AddrStd(
                    ton_block::MsgAddrStd {
                        workchain_id: 0,
                        address: address.into(),
                        anycast: None,
                    },
                ))
                .pack_into_chain(&ton_abi::contract::ABI_VERSION_2_2)
                .trust_me(),
            )
            .trust_me();

        self.state.data = Some(self.data.serialize().trust_me());

        self.state.serialize().trust_me().repr_hash()
    }
}

fn load_token_state() -> ton_block::StateInit {
    ton_block::StateInit::construct_from_bytes(include_bytes!("TokenWalletPlatform.tvc"))
        .expect("Shouldn't fail")
}

static BITS: [u8; 16] = [4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn correct_token_wallet_address() {
        let mut wever = TokenState::new(
            ton_block::MsgAddressInt::from_str(
                "0:a49cd4e158a9a15555e624759e2e4e766d22600b7800d891e46f9291f044a93d",
            )
            .unwrap(),
        );

        let token_address = wever.compute_address(
            ton_types::UInt256::from_str(
                "6fa537fa97adf43db0206b5bec98eb43474a9836c016a190ac8b792feb852230",
            )
            .unwrap(),
        );
        assert_eq!(
            token_address.as_hex_string(),
            "4a64bb41cb22e0fd85b42ddc20da31a90c6939677db3b09b1b369a01ae814cc9"
        );
    }
}
