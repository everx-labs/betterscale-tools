use anyhow::{Context, Result};
use ton_types::IBitstring;

use crate::ed25519::*;

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
    data.append_bits(0, 3).unwrap(); // empty dict, empty dict, empty dict
    data.append_bits(0, 4).unwrap(); // grams
    data.append_bits(0, 32).unwrap(); // uint32
    data.append_raw(&[0; 32], 256).unwrap(); // uint256

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

fn make_address(address: ton_types::UInt256) -> Result<ton_block::MsgAddressInt> {
    ton_block::MsgAddressInt::with_standart(
        None,
        -1,
        ton_types::SliceData::from_raw(address.as_slice().to_vec(), 256),
    )
    .context("Failed to create address")
}

static CONFIG_CODE: &[u8] = include_bytes!("config_code.boc");
static ELECTOR_CODE: &[u8] = include_bytes!("elector_code.boc");
