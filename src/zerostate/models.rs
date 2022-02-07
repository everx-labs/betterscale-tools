use std::collections::HashMap;
use std::str::FromStr;

use nekoton_utils::*;
use num_bigint::BigInt;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ZerostateConfig {
    pub global_id: i32,
    pub gen_utime: u32,
    #[serde(with = "serde_uint256")]
    pub config_public_key: ton_types::UInt256,
    #[serde(with = "serde_uint256")]
    pub minter_public_key: ton_types::UInt256,

    #[serde(with = "serde_account_states")]
    pub accounts: HashMap<ton_types::UInt256, ton_block::Account>,
    pub config: NetworkConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(with = "serde_uint256")]
    pub config_address: ton_types::UInt256,
    #[serde(with = "serde_uint256")]
    pub elector_address: ton_types::UInt256,
    #[serde(with = "serde_uint256")]
    pub minter_address: ton_types::UInt256,
    pub currencies: Vec<Currency>,
    pub global_version: u32,
    #[serde(with = "serde_hex_number")]
    pub global_capabilities: u64,
    pub mandatory_params: Vec<u32>,
    pub critical_params: Vec<u32>,
    pub voting_setup: Option<ConfigVotingSetup>,
    pub workchains: Vec<WorkchainDescription>,
    pub block_creation_fees: BlockCreationFees,
    pub elector_params: ElectorParams,
    pub validator_count: ValidatorCount,
    pub stake_params: StakeParams,
    pub storage_prices: Vec<StoragePrices>,
    pub gas_prices: GasPrices,
    pub block_limits: BlockLimits,
    pub msg_forward_prices: MsgForwardPrices,
    pub catchain_params: CatchainParams,
    pub consensus_params: ConsensusParams,
    #[serde(with = "serde_vec_uint256")]
    pub fundamental_addresses: Vec<ton_types::UInt256>,
    pub validator_set: ValidatorSet,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Currency {
    pub id: u32,
    #[serde(with = "serde_string")]
    pub total_supply: BigInt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigVotingSetup {
    pub normal_params: ConfigVotingParams,
    pub critical_params: ConfigVotingParams,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigVotingParams {
    pub min_total_rounds: u8,
    pub max_total_rounds: u8,
    pub min_wins: u8,
    pub max_losses: u8,
    pub min_store_sec: u32,
    pub max_store_sec: u32,
    pub bit_price: u32,
    pub cell_price: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkchainDescription {
    pub workchain_id: u32,
    pub enabled_since: u32,
    pub min_split: u8,
    pub max_split: u8,
    #[serde(default)]
    pub flags: u16,
    pub active: bool,
    pub accept_msgs: bool,
    pub vm_version: i32,
    #[serde(with = "serde_hex_number")]
    pub vm_mode: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockCreationFees {
    #[serde(with = "serde_amount")]
    pub masterchain_block_fee: u64,
    #[serde(with = "serde_amount")]
    pub basechain_block_fee: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectorParams {
    pub validators_elected_for: u32,
    pub elections_start_before: u32,
    pub elections_end_before: u32,
    pub stake_held_for: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorCount {
    pub min_validators: u32,
    pub max_validators: u32,
    pub max_main_validators: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StakeParams {
    #[serde(with = "serde_amount")]
    pub min_stake: u64,
    #[serde(with = "serde_amount")]
    pub max_stake: u64,
    #[serde(with = "serde_amount")]
    pub min_total_stake: u64,
    pub max_stake_factor: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePrices {
    pub utime_since: u32,
    #[serde(with = "serde_amount")]
    pub bit_price_ps: u64,
    #[serde(with = "serde_amount")]
    pub cell_price_ps: u64,
    #[serde(with = "serde_amount")]
    pub mc_bit_price_ps: u64,
    #[serde(with = "serde_amount")]
    pub mc_cell_price_ps: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GasPrices {
    pub masterchain: GasPricesEntry,
    pub basechain: GasPricesEntry,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GasPricesEntry {
    #[serde(with = "serde_amount")]
    pub gas_price: u64,
    #[serde(with = "serde_amount")]
    pub gas_limit: u64,
    #[serde(with = "serde_amount")]
    pub special_gas_limit: u64,
    #[serde(with = "serde_amount")]
    pub gas_credit: u64,
    #[serde(with = "serde_amount")]
    pub block_gas_limit: u64,
    #[serde(with = "serde_amount")]
    pub freeze_due_limit: u64,
    #[serde(with = "serde_amount")]
    pub delete_due_limit: u64,
    #[serde(with = "serde_amount")]
    pub flat_gas_limit: u64,
    #[serde(with = "serde_amount")]
    pub flat_gas_price: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockLimits {
    pub masterchain: BlockLimitsEntry,
    pub basechain: BlockLimitsEntry,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockLimitsEntry {
    pub bytes: BlockLimitsParam,
    pub gas: BlockLimitsParam,
    pub lt_delta: BlockLimitsParam,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockLimitsParam {
    pub underload: u32,
    pub soft_limit: u32,
    pub hard_limit: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgForwardPrices {
    pub masterchain: MsgForwardPricesEntry,
    pub basechain: MsgForwardPricesEntry,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgForwardPricesEntry {
    #[serde(with = "serde_amount")]
    pub lump_price: u64,
    #[serde(with = "serde_amount")]
    pub bit_price: u64,
    #[serde(with = "serde_amount")]
    pub cell_price: u64,
    pub ihr_price_factor: u32,
    pub first_frac: u16,
    pub next_frac: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatchainParams {
    pub shuffle_mc_validators: bool,
    #[serde(default)]
    pub isolate_mc_validators: bool,
    pub mc_catchain_lifetime: u32,
    pub shard_catchain_lifetime: u32,
    pub shard_validators_lifetime: u32,
    pub shard_validators_num: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsensusParams {
    pub new_catchain_ids: bool,
    pub round_candidates: u32,
    pub next_candidate_delay_ms: u32,
    pub consensus_timeout_ms: u32,
    pub fast_attempts: u32,
    pub attempt_duration: u32,
    pub catchain_max_deps: u32,
    pub max_block_bytes: u32,
    pub max_collated_bytes: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorSet {
    pub validators: Vec<ValidatorSetEntry>,
    pub utime_since: u32,
    pub utime_until: u32,
    pub main: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorSetEntry {
    #[serde(with = "serde_hex_array")]
    pub public_key: [u8; 32],
    #[serde(with = "serde_amount")]
    pub weight: u64,
}

mod serde_account_states {
    use super::*;

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<ton_types::UInt256, ton_block::Account>, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::Error;
        use ton_block::Deserializable;

        let map = HashMap::<String, String>::deserialize(deserializer)?;
        map.into_iter()
            .map(|(key, value)| {
                let address = ton_types::UInt256::from_str(&key).map_err(D::Error::custom)?;
                let state =
                    ton_block::Account::construct_from_base64(&value).map_err(D::Error::custom)?;
                Ok((address, state))
            })
            .collect()
    }
}

mod serde_hex_number {
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use serde::de::{Deserialize, Error};

        let value = String::deserialize(deserializer)?;
        u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(D::Error::custom)
    }
}

mod serde_amount {
    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StringOrNumber::deserialize(deserializer).map(|StringOrNumber(x)| x)
    }
}

struct StringOrNumber(u64);

impl<'de> Deserialize<'de> for StringOrNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Value<'a> {
            String(&'a str),
            Number(u64),
        }

        match Value::deserialize(deserializer)? {
            Value::String(str) => u64::from_str(str)
                .map(Self)
                .map_err(|_| D::Error::custom("Invalid number")),
            Value::Number(value) => Ok(Self(value)),
        }
    }
}
