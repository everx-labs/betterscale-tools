use std::str::FromStr;

use anyhow::{Context, Result};
use ton_block::{Deserializable, GetRepresentationHash, Serializable};
use ton_types::{IBitstring, SliceData};

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

    account.set_balance(ton_block::CurrencyCollection::default());
    Ok(account)
}

pub fn build_config_state(
    address: ton_types::UInt256,
    pubkey: PublicKey,
) -> Result<ton_block::Account> {
    let address = make_address(address)?;

    let balance = ton_block::CurrencyCollection::from_grams(500_000_000_000u64.into());

    let mut code = CONFIG_CODE;
    let code =
        ton_types::deserialize_tree_of_cells(&mut code).context("Failed to read config code")?;

    let mut data = ton_types::BuilderData::new();
    data.checked_append_reference(ton_types::Cell::default())?;
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
            init_code_hash: None,
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

    let mut code = ELECTOR_CODE;
    let code =
        ton_types::deserialize_tree_of_cells(&mut code).context("Failed to read elector code")?;

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
            init_code_hash: None,
        },
    });
    account
        .update_storage_stat()
        .context("Failed to update storage stat")?;

    Ok(account)
}

pub fn build_giver(
    balance: u128,
    pubkey: PublicKey,
) -> Result<(ton_types::UInt256, ton_block::Account)> {
    let mut account = ton_block::Account::construct_from_bytes(GIVER_STATE)
        .context("Failed to read giver state")?;

    let state_init = account.state_init_mut().expect("Shouldn't fail");
    if let Some(data) = state_init.data.take() {
        let mut data = SliceData::load_cell(data)?;
        data.move_by(256).expect("invalid giver state");

        let mut new_data = ton_types::BuilderData::new();
        new_data
            .append_raw(pubkey.as_bytes(), 256)?
            .append_builder(&ton_types::BuilderData::from_slice(&data))?;

        state_init.data = Some(new_data.into_cell()?);
    }

    // Compute address
    let address = state_init
        .hash()
        .context("Failed to serialize state init")?;

    account.set_balance(ton_block::CurrencyCollection::from_grams(
        ton_block::Grams::new(balance)?,
    ));

    account
        .update_storage_stat()
        .context("Failed to update storage stat")?;

    Ok((address, account))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MultisigType {
    SafeMultisig,
    SetcodeMultisig,
    Multisig2,
}

impl FromStr for MultisigType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "SafeMultisig" | "SafeMultisigWallet" => Self::SafeMultisig,
            "SetcodeMultisig" | "SetcodeMultisigWallet" => Self::SetcodeMultisig,
            "Multisig2" | "multisig2" => Self::Multisig2,
            _ => anyhow::bail!("Unknown wallet type"),
        })
    }
}

pub struct MultisigBuilder {
    pubkey: PublicKey,
    custodians: Vec<PublicKey>,
    required_confirms: Option<u8>,
    lifetime: Option<u32>,
    ty: MultisigType,
}

impl MultisigBuilder {
    pub fn new(pubkey: PublicKey, ty: MultisigType) -> Self {
        Self {
            pubkey,
            custodians: Vec::new(),
            required_confirms: None,
            lifetime: None,
            ty,
        }
    }

    pub fn custodians(mut self, custodians: Vec<PublicKey>) -> Self {
        self.custodians = custodians;
        self
    }

    pub fn required_confirms(mut self, required_confirms: Option<u8>) -> Self {
        self.required_confirms = required_confirms;
        self
    }

    pub fn lifetime(mut self, lifetime: Option<u32>) -> Self {
        self.lifetime = lifetime;
        self
    }

    pub fn build_with_balance(
        mut self,
        balance: u128,
    ) -> Result<(ton_types::UInt256, ton_block::Account)> {
        const DEFAULT_LIFETIME: u32 = 3600;

        if let Some(lifetime) = self.lifetime {
            anyhow::ensure!(
                self.ty == MultisigType::Multisig2,
                "Custom lifetime is not supported by this multisig type"
            );
            anyhow::ensure!(lifetime > 600, "Transaction lifetime is too small");
        }

        let code = ton_types::deserialize_tree_of_cells(&mut match self.ty {
            MultisigType::SafeMultisig => MULTISIG_CODE,
            MultisigType::SetcodeMultisig => SETCODE_MULTISIG_CODE,
            MultisigType::Multisig2 => MULTISIG2_CODE,
        })
        .context("Failed to read multisig code")?;

        let custodian_count = match self.custodians.len() {
            0 => {
                self.custodians.push(self.pubkey);
                1 // set deployer as the single custodian
            }
            len if len <= 32 => len as u8,
            _ => return Err(anyhow::anyhow!("Too many custodians")),
        };

        // All confirmations are required if it wasn't explicitly specified
        let required_confirms = self.required_confirms.unwrap_or(custodian_count);

        // Compute address
        let mut init_params = ton_types::HashmapE::with_bit_len(64);
        init_params.set(
            0u64.serialize().and_then(SliceData::load_cell)?,
            &ton_types::SliceData::from_raw(self.pubkey.as_bytes().to_vec(), 256),
        )?;

        if self.ty != MultisigType::Multisig2 {
            let key = 8u64.serialize().and_then(SliceData::load_cell)?;

            init_params.set(key, &{
                let key = 0u64.serialize().and_then(SliceData::load_cell)?;
                let mut map = ton_types::HashmapE::with_bit_len(64);
                map.set(key, &Default::default())?;
                map.serialize().and_then(SliceData::load_cell)?
            })?;
        }

        let mut state_init = ton_block::StateInit {
            code: Some(code),
            data: Some(init_params.serialize()?),
            ..Default::default()
        };
        let address = state_init
            .hash()
            .context("Failed to serialize state init")?;

        // Compute data params
        let owner_key = self.custodians.first().unwrap_or(&self.pubkey).as_bytes();

        let mut custodians = ton_types::HashmapE::with_bit_len(256);
        for (i, pubkey) in self.custodians.iter().enumerate() {
            custodians.set(
                ton_types::SliceData::from_raw(pubkey.as_bytes().to_vec(), 256),
                &ton_types::SliceData::from_raw(vec![i as u8], 8),
            )?;
        }

        let default_required_confirmations = std::cmp::min(required_confirms, custodian_count);

        let required_votes = if custodian_count <= 2 {
            custodian_count
        } else {
            (custodian_count * 2 + 1) / 3
        };

        let mut data = ton_types::BuilderData::new();

        // Write headers
        data.append_raw(self.pubkey.as_bytes(), 256)?; // pubkey
        data.append_u64(0)?; // time
        data.append_bit_one()?; // constructor flag

        // Write state variables
        match self.ty {
            MultisigType::SafeMultisig => {
                data.append_raw(owner_key, 256)?; // m_ownerKey
                data.append_raw(&[0; 32], 256)?; // m_requestsMask
                data.append_u8(custodian_count)?; // m_custodianCount
                data.append_u8(default_required_confirmations)?; // m_defaultRequiredConfirmations
                data.append_bit_zero()?; // empty m_transactions
                custodians.write_to(&mut data)?; // m_custodians
            }
            MultisigType::SetcodeMultisig => {
                data.append_raw(owner_key, 256)?; // m_ownerKey
                data.append_raw(&[0; 32], 256)?; // m_requestsMask
                data.append_u8(custodian_count)?; // m_custodianCount
                data.append_u32(0)?; // m_updateRequestsMask
                data.append_u8(required_votes)?; // m_requiredVotes

                let mut updates = ton_types::BuilderData::new();
                updates.append_bit_zero()?; // empty m_updateRequests
                data.checked_append_reference(updates.into_cell()?)?; // sub reference

                data.append_u8(default_required_confirmations)?; // m_defaultRequiredConfirmations
                data.append_bit_zero()?; // empty m_transactions
                custodians.write_to(&mut data)?; // m_custodians
            }
            MultisigType::Multisig2 => {
                data.append_raw(owner_key, 256)?; // m_ownerKey
                data.append_raw(&[0; 32], 256)?; // m_requestsMask
                data.append_bit_zero()?; // empty m_transactions
                custodians.write_to(&mut data)?; // m_custodians
                data.append_u8(custodian_count)?; // m_custodianCount
                data.append_bit_zero()?; // empty m_updateRequests
                data.append_u32(0)?; // m_updateRequestsMask
                data.append_u8(required_votes)?; // m_requiredVotes
                data.append_u8(default_required_confirmations)?; // m_defaultRequiredConfirmations
                data.append_u32(self.lifetime.unwrap_or(DEFAULT_LIFETIME))?;
            }
        };

        // "Deploy" wallet
        state_init.data = Some(data.into_cell()?);

        // Done
        let mut account = ton_block::Account::Account(ton_block::AccountStuff {
            addr: make_address(address).context("Failed to create validator address")?,
            storage_stat: Default::default(),
            storage: ton_block::AccountStorage {
                last_trans_lt: 0,
                balance: ton_block::CurrencyCollection::from_grams(ton_block::Grams::new(balance)?),
                state: ton_block::AccountState::AccountActive { state_init },
                init_code_hash: None,
            },
        });
        account
            .update_storage_stat()
            .context("Failed to update storage stat")?;

        Ok((address, account))
    }
}

pub fn build_ever_wallet(
    balance: u128,
    pubkey: PublicKey,
) -> Result<(ton_types::UInt256, ton_block::Account)> {
    let mut data = ton_types::BuilderData::new();
    data.append_raw(pubkey.as_bytes(), 256)?.append_u64(0)?;
    let data = data.into_cell()?;

    let state_init = ton_block::StateInit {
        code: Some(nekoton::contracts::wallets::code::ever_wallet()),
        data: Some(data),
        ..Default::default()
    };

    let address = state_init
        .hash()
        .context("Failed to serialize state init")?;

    let mut account = ton_block::Account::Account(ton_block::AccountStuff {
        addr: make_address(address).context("Failed to create validator address")?,
        storage_stat: Default::default(),
        storage: ton_block::AccountStorage {
            last_trans_lt: 0,
            balance: ton_block::CurrencyCollection::from_grams(ton_block::Grams::new(balance)?),
            state: ton_block::AccountState::AccountActive { state_init },
            init_code_hash: None,
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
static MINTER_STATE: &[u8] = include_bytes!("minter_state.boc");
static GIVER_STATE: &[u8] = include_bytes!("giver_state.boc");
static MULTISIG_CODE: &[u8] = include_bytes!("multisig_code.boc");
static MULTISIG2_CODE: &[u8] = include_bytes!("multisig2_code.boc");
static SETCODE_MULTISIG_CODE: &[u8] = include_bytes!("setcode_multisig_code.boc");

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn test_pubkey() -> PublicKey {
        PublicKey::from_bytes(
            hex::decode("1161f67ca580dd2b9935967b04109e0e988601fc0894e145f7cd56534e817257")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn check_safe_multisig_address() {
        assert_eq!(
            MultisigBuilder::new(test_pubkey(), MultisigType::SafeMultisig)
                .build_with_balance(1000)
                .unwrap()
                .0,
            ton_types::UInt256::from_str(
                "9d98e2c829b309abebfa1d3745a62a8b11b68233a1b5d1044f6e09e380d67b97"
            )
            .unwrap()
        );
    }

    #[test]
    fn check_setcode_multisig_address() {
        assert_eq!(
            MultisigBuilder::new(test_pubkey(), MultisigType::Multisig2)
                .build_with_balance(1000)
                .unwrap()
                .0,
            ton_types::UInt256::from_str(
                "216fe0928d90f103434f9fb826dd66a405e42e92660598496912499a199bbfe5"
            )
            .unwrap()
        )
    }
}
