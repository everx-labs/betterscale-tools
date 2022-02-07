use anyhow::{Context, Result};
use ton_block::{Deserializable, GetRepresentationHash, Serializable};
use ton_types::IBitstring;

use crate::ed25519::*;

pub fn build_minter(pubkey: PublicKey) -> Result<ton_block::Account> {
    let mut account = ton_block::Account::construct_from_bytes(MINTER_STATE)?;

    if let ton_block::Account::Account(stuff) = &mut account {
        if let ton_block::AccountState::AccountActive { state_init, .. } = &mut stuff.storage.state
        {
            let mut data = ton_types::BuilderData::new();
            data.append_u32(0)?; // seqno
            data.append_raw(pubkey.as_bytes(), 256)?; // pubkey

            state_init.data = Some(data.into_cell()?);
        }
    }

    Ok(account)
}

pub fn build_tick_tock() -> Result<(ton_types::UInt256, ton_block::Account)> {
    let account = ton_block::Account::construct_from_bytes(TICK_TOCK_STATE)?;

    let address = account
        .state_init()
        .context("Empty tick tock account")?
        .hash()
        .context("Failed to compute tick tock hash")?;

    Ok((address, account))
}

pub fn build_config_state(
    address: ton_types::UInt256,
    pubkey: PublicKey,
) -> Result<ton_block::Account> {
    let address = make_address(address)?;

    let balance = ton_block::CurrencyCollection::from_grams(500_000_000_000u64.into());

    let code = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(CONFIG_CODE))
        .context("Failed to read config code")?;

    let mut data = ton_types::BuilderData::new();
    data.append_reference(ton_types::BuilderData::default());
    data.append_u32(0)?;
    data.append_raw(pubkey.as_bytes(), 256)?;
    data.append_bits(0, 1)?;

    let mut account = ton_block::Account::Account(ton_block::AccountStuff {
        addr: address,
        storage_stat: Default::default(),
        storage: ton_block::AccountStorage {
            last_trans_lt: 0,
            balance,
            state: ton_block::AccountState::AccountActive {
                init_code_hash: None,
                state_init: ton_block::StateInit {
                    split_depth: None,
                    special: Some(ton_block::TickTock {
                        tick: false,
                        tock: true,
                    }),
                    code: Some(code),
                    data: Some(data.into_cell()?),
                    library: Default::default(),
                },
            },
        },
    });
    account
        .update_storage_stat()
        .context("Failed to update storage stat")?;

    Ok(account)
}

pub fn build_elector_state(address: ton_types::UInt256) -> Result<ton_block::Account> {
    let address = make_address(address)?;

    let balance = ton_block::CurrencyCollection::from_grams(500_000_000_000u64.into());

    let code = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(ELECTOR_CODE))
        .context("Failed to read elector code")?;

    let mut data = ton_types::BuilderData::new();
    data.append_bits(0, 3)?; // empty dict, empty dict, empty dict
    data.append_bits(0, 4)?; // grams
    data.append_bits(0, 32)?; // uint32
    data.append_raw(&[0; 32], 256)?; // uint256

    let mut account = ton_block::Account::Account(ton_block::AccountStuff {
        addr: address,
        storage_stat: Default::default(),
        storage: ton_block::AccountStorage {
            last_trans_lt: 0,
            balance,
            state: ton_block::AccountState::AccountActive {
                init_code_hash: None,
                state_init: ton_block::StateInit {
                    split_depth: None,
                    special: Some(ton_block::TickTock {
                        tick: true,
                        tock: false,
                    }),
                    code: Some(code),
                    data: Some(data.into_cell()?),
                    library: Default::default(),
                },
            },
        },
    });
    account
        .update_storage_stat()
        .context("Failed to update storage stat")?;

    Ok(account)
}

pub fn build_validator_wallet(
    pubkey: PublicKey,
    balance: u64,
) -> Result<(ton_types::UInt256, ton_block::Account)> {
    let code = ton_types::deserialize_tree_of_cells(&mut std::io::Cursor::new(MULTISIG_CODE))
        .context("Failed to read multisig code")?;

    // Compute address
    let mut init_params = ton_types::HashmapE::with_bit_len(64);
    init_params.set(
        0u64.serialize()?.into(),
        &ton_types::SliceData::from_raw(pubkey.as_bytes().to_vec(), 256),
    )?;
    init_params.set(8u64.serialize()?.into(), &{
        let mut map = ton_types::HashmapE::with_bit_len(64);
        map.set(0u64.serialize()?.into(), &Default::default())?;
        map.serialize()?.into()
    })?;

    let mut state_init = ton_block::StateInit {
        code: Some(code),
        data: Some(init_params.serialize()?),
        ..Default::default()
    };
    let address = state_init
        .hash()
        .context("Failed to serialize state init")?;

    // Build data
    let mut data = ton_types::BuilderData::new();
    data.append_raw(pubkey.as_bytes(), 256)?; // pubkey
    data.append_u64(0)?; // time
    data.append_bit_one()?; // constructor flag

    data.append_raw(pubkey.as_bytes(), 256)?; // m_ownerKey
    data.append_raw(&[0; 32], 256)?; // m_requestsMask

    data.append_u8(1)?; // m_custodianCount
    data.append_u8(1)?; // m_defaultRequiredConfirmations

    data.append_bit_zero()?; // empty m_transactions

    let mut custodians = ton_types::HashmapE::with_bit_len(256);
    custodians.set(
        ton_types::SliceData::from_raw(pubkey.as_bytes().to_vec(), 256),
        &ton_types::SliceData::from_raw(vec![0], 8),
    )?;
    custodians.write_to(&mut data)?; // m_custodians

    // "Deploy" wallet
    state_init.data = Some(data.into_cell()?);

    // Done
    let mut account = ton_block::Account::Account(ton_block::AccountStuff {
        addr: make_address(address).context("Failed to create validator address")?,
        storage_stat: Default::default(),
        storage: ton_block::AccountStorage {
            last_trans_lt: 0,
            balance: ton_block::CurrencyCollection::from_grams(ton_block::Grams::from(balance)),
            state: ton_block::AccountState::AccountActive {
                init_code_hash: None,
                state_init,
            },
        },
    });
    account
        .update_storage_stat()
        .context("Failed to update storage stat")?;

    Ok((address, account))
}

fn make_address(address: ton_types::UInt256) -> Result<ton_block::MsgAddressInt> {
    ton_block::MsgAddressInt::with_standart(None, -1, address.into())
        .context("Failed to create address")
}

static CONFIG_CODE: &[u8] = include_bytes!("config_code.boc");
static ELECTOR_CODE: &[u8] = include_bytes!("elector_code.boc");
static TICK_TOCK_STATE: &[u8] = include_bytes!("tick_tock_state.boc");
static MINTER_STATE: &[u8] = include_bytes!("minter_state.boc");

static MULTISIG_CODE: &[u8] = include_bytes!("multisig_code.boc");

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use ton_block::HashmapAugType;

    use super::*;

    #[test]
    fn check_validator_address() {
        let pubkey =
            hex::decode("1161f67ca580dd2b9935967b04109e0e988601fc0894e145f7cd56534e817257")
                .unwrap();
        let pubkey = PublicKey::from_bytes(pubkey.try_into().unwrap()).unwrap();

        assert_eq!(
            build_validator_wallet(pubkey, 1000).unwrap().0,
            ton_types::UInt256::from_str(
                "9d98e2c829b309abebfa1d3745a62a8b11b68233a1b5d1044f6e09e380d67b97"
            )
            .unwrap()
        );
    }

    #[test]
    fn check_tick_tock_address() {
        assert_eq!(
            build_tick_tock().unwrap().0,
            ton_types::UInt256::from_str(
                "04f64c6afbff3dd10d8ba6707790ac9670d540f37a9448b0337baa6a5a92acac"
            )
            .unwrap()
        );
    }
}
