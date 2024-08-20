use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use everscale_crypto::ed25519;
use nekoton::core::generic_contract::*;
use nekoton::core::models::{
    ContractState, PendingTransaction, Transaction, TransactionsBatchInfo,
};
use nekoton::transport::models::*;
use nekoton::transport::Transport;
use nekoton_transport::gql::*;
use nekoton_transport::jrpc::*;
use nekoton_utils::{SimpleClock, TrustMe};
use serde::Deserialize;
use tokio::sync::oneshot;
use ton_block::{ConfigParamEnum, Serializable};
use ton_types::{BuilderData, Cell, IBitstring, SliceData};

use crate::models::*;

pub async fn set_param(
    url: String,
    config: &ton_block::MsgAddressInt,
    secret: &ed25519::SecretKey,
    param: ParamToChange,
) -> Result<()> {
    ConfigContract::subscribe(url, config)
        .await?
        .execute_action(secret, Action::SubmitParam(param.into_param()?))
        .await
}

pub async fn set_master_key(
    url: String,
    config: &ton_block::MsgAddressInt,
    secret: &ed25519::SecretKey,
    master_key: ed25519::PublicKey,
) -> Result<()> {
    ConfigContract::subscribe(url, config)
        .await?
        .execute_action(secret, Action::UpdateMasterKey(master_key))
        .await
}

pub async fn set_elector_code(
    url: String,
    config: &ton_block::MsgAddressInt,
    secret: &ed25519::SecretKey,
    code: Cell,
    params: Option<SliceData>,
) -> Result<()> {
    ConfigContract::subscribe(url, config)
        .await?
        .execute_action(secret, Action::UpdateElectorCode { code, params })
        .await
}

macro_rules! define_params(
    (
        $(#[$outer:ident $($outer_args:tt)*])*
        $vis:vis enum $type:ident {
            $(
                #[doc = $desc:literal]
                $variant:ident($variant_type:ident) => |$value:ident| $expr:expr
            ),*
            $(,)?
        }
    ) => {
        $(#[$outer $($outer_args)*])*
        $vis enum $type {
            $(#[doc = $desc] $variant($variant_type)),*,
        }

        impl $type {
            #[allow(clippy::format_push_string)]
            pub fn description() -> String {
                let mut description = String::new();
                $(description += &format!("{}:{}\n", stringify!($variant).to_lowercase(), $desc);)*
                description
            }

            pub fn into_param(self) -> Result<ConfigParamEnum> {
                Ok(match self {
                    $(Self::$variant($value) => $expr),*,
                })
            }
        }
    };
);

define_params! {
    #[derive(Deserialize)]
    #[serde(
        tag = "param",
        content = "value",
        rename_all = "camelCase",
        deny_unknown_fields
    )]
    pub enum ParamToChange {
        /// Global nodes version and capabilities
        P8(GlobalVersion) => |v| ConfigParamEnum::ConfigParam8(v.build()),
        /// Mandatory params
        P9(MandatoryParams) => |v| {
            ConfigParamEnum::ConfigParam9(ton_block::ConfigParam9 {
                mandatory_params: v.build()?
            })
        },
        /// Critical params
        P10(MandatoryParams) => |v| {
            ConfigParamEnum::ConfigParam10(ton_block::ConfigParam10 {
                critical_params: v.build()?
            })
        },
        /// Workchains
        P12(Workchains) => |v| {
            ConfigParamEnum::ConfigParam12(v.build(ConfigBuildContext::Update)?)
        },
        /// Block creation fees
        P14(BlockCreationFees) => |v| ConfigParamEnum::ConfigParam14(v.build()),
        /// Elector params
        P15(ElectorParams) => |v| ConfigParamEnum::ConfigParam15(v.build()),
        /// Validator count
        P16(ValidatorCount) => |v| ConfigParamEnum::ConfigParam16(v.build()),
        /// Stake params
        P17(StakeParams) => |v| ConfigParamEnum::ConfigParam17(v.build()),
        /// Storage prices
        P18(StoragePricesCollection) => |v| ConfigParamEnum::ConfigParam18(v.build()?),
        /// Masterchain gas prices
        P20(GasPricesEntry) => |v| ConfigParamEnum::ConfigParam20(v.build()),
        /// Basechain gas prices
        P21(GasPricesEntry) => |v| ConfigParamEnum::ConfigParam21(v.build()),
        /// Masterchain block limits
        P22(BlockLimitsEntry) => |v| ConfigParamEnum::ConfigParam22(v.build()?),
        /// Basechain block limits
        P23(BlockLimitsEntry) => |v| ConfigParamEnum::ConfigParam23(v.build()?),
        /// Masterchain message forward prices
        P24(MsgForwardPricesEntry) => |v| ConfigParamEnum::ConfigParam24(v.build()),
        /// Basechain message forward prices
        P25(MsgForwardPricesEntry) => |v| ConfigParamEnum::ConfigParam25(v.build()),
        /// Catchain config
        P28(CatchainParams) => |v| ConfigParamEnum::ConfigParam28(v.build()),
        /// Consensus config
        P29(ConsensusParams) => |v| ConfigParamEnum::ConfigParam29(v.build()),

        /// Banned accounts by address
        P44(BannedAccountsByAddress) => |v| v.build().unwrap(),

        /// Transaction tree limits
        P50(TransactionTreeLimits) => |v| v.build().unwrap(),
    }
}

type Workchains = Vec<WorkchainDescription>;

struct ConfigContract {
    address: ton_block::MsgAddressInt,
    transport: Arc<dyn Transport>,
    handler: Arc<ConfigContractHandler>,
    subscription: Arc<tokio::sync::Mutex<GenericContract>>,
}

impl ConfigContract {
    async fn subscribe(url: String, address: &ton_block::MsgAddressInt) -> Result<Self> {
        let transport = make_client(url)?;

        let clock = Arc::new(SimpleClock);
        let handler = Arc::new(ConfigContractHandler::default());

        let subscription = Arc::new(tokio::sync::Mutex::new(
            GenericContract::subscribe(
                clock,
                transport.clone(),
                address.clone(),
                handler.clone(),
                false,
            )
            .await
            .context("Failed to create config contract subscription")?,
        ));

        tokio::spawn({
            let subscription = subscription.clone();
            async move {
                loop {
                    if let Err(e) = subscription.lock().await.refresh().await {
                        eprintln!("Failed to update config subscription: {e:?}");
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        });

        Ok(Self {
            address: address.clone(),
            transport,
            handler,
            subscription,
        })
    }

    async fn execute_action(&self, secret: &ed25519::SecretKey, action: Action) -> Result<()> {
        let signature_id = self
            .transport
            .get_capabilities(&SimpleClock)
            .await
            .context("Failed to get capabilities")?
            .signature_id();

        let seqno = self
            .check_state(Some(ed25519::PublicKey::from(secret)))
            .await?;

        let (message, expire_at) = create_message(
            seqno,
            &self.address,
            action,
            ed25519::KeyPair::from(secret),
            signature_id,
            60,
        )
        .context("Failed to create action message")?;

        self.send_message(message, expire_at)
            .await
            .context("Failed to execute action")
    }

    async fn send_message(&self, message: ton_block::Message, expire_at: u32) -> Result<()> {
        let message_hash = message.serialize()?.repr_hash();

        let (tx, rx) = oneshot::channel();
        self.handler.0.lock().insert(message_hash, tx);

        self.subscription
            .lock()
            .await
            .send(&message, expire_at)
            .await?;

        if rx.await.context("Sender dropped")? {
            Ok(())
        } else {
            Err(ConfigError::MessageExpired.into())
        }
    }

    async fn check_state(&self, required_public: Option<ed25519::PublicKey>) -> Result<u32> {
        let config_state = match self.transport.get_contract_state(&self.address).await? {
            RawContractState::Exists(contract) => contract.account,
            RawContractState::NotExists { .. } => return Err(ConfigError::ConfigNotExists.into()),
        };

        let mut data: SliceData = match config_state.storage.state {
            ton_block::AccountState::AccountActive { state_init, .. } => state_init.data,
            _ => None,
        }
        .map(SliceData::load_cell)
        .transpose()?
        .ok_or(ConfigError::InvalidState)?;

        let seqno = data.get_next_u32().context("Failed to get seqno")?;
        if let Some(required_public) = required_public {
            let public = data
                .get_next_bytes(32)
                .context("Failed to get public key")?;
            let public = ton_types::UInt256::from_be_bytes(&public);

            if public.as_slice() != required_public.as_bytes() {
                return Err(ConfigError::PublicKeyMismatch.into());
            }
        }

        Ok(seqno)
    }
}

#[derive(Default)]
struct ConfigContractHandler(parking_lot::Mutex<HashMap<ton_types::UInt256, MessageTx>>);

impl GenericContractSubscriptionHandler for ConfigContractHandler {
    fn on_message_sent(&self, pending_transaction: PendingTransaction, _: Option<Transaction>) {
        let mut messages = self.0.lock();
        if let Some(tx) = messages.remove(&pending_transaction.message_hash) {
            tx.send(true).ok();
        }
    }

    fn on_message_expired(&self, pending_transaction: PendingTransaction) {
        let mut messages = self.0.lock();
        if let Some(tx) = messages.remove(&pending_transaction.message_hash) {
            tx.send(false).ok();
        }
    }

    fn on_state_changed(&self, _: ContractState) {}
    fn on_transactions_found(&self, _: Vec<Transaction>, _: TransactionsBatchInfo) {}
}

pub fn create_message(
    seqno: u32,
    address: &ton_block::MsgAddressInt,
    action: Action,
    keys: ed25519::KeyPair,
    signature_id: Option<i32>,
    timeout: u32,
) -> Result<(ton_block::Message, u32)> {
    let (action, data) = action.build().context("Failed to build action")?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .trust_me()
        .as_secs() as u32;
    let expire_at = now + timeout;

    let mut builder = BuilderData::new();
    builder
        .append_u32(action)? // action
        .append_u32(seqno)? // msg_seqno
        .append_u32(expire_at)? // valid_until
        .append_builder(&data)?; // action data

    let hash = builder.clone().into_cell()?.repr_hash();

    let data = match signature_id {
        Some(signature_id) => {
            let mut result = Vec::with_capacity(4 + 32);
            result.extend_from_slice(&signature_id.to_be_bytes());
            result.extend_from_slice(hash.as_slice());
            std::borrow::Cow::<[u8]>::Owned(result)
        }
        None => std::borrow::Cow::<[u8]>::Borrowed(hash.as_slice()),
    };

    let signature = keys.sign_raw(data.as_ref());
    builder.prepend_raw(&signature, 512)?;

    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst: address.clone(),
            ..Default::default()
        });
    message.set_body(SliceData::load_builder(builder)?);

    Ok((message, expire_at))
}

fn make_client(url: String) -> Result<Arc<dyn Transport>> {
    if url.ends_with("rpc") {
        let client = JrpcClient::new(url).context("Failed to create jrpc client")?;

        Ok(Arc::new(nekoton::transport::jrpc::JrpcTransport::new(
            client,
        )))
    } else {
        let client = GqlClient::new(GqlNetworkSettings {
            endpoints: vec![url],
            latency_detection_interval: Duration::from_secs(1),
            ..Default::default()
        })?;

        Ok(Arc::new(nekoton::transport::gql::GqlTransport::new(client)))
    }
}

#[derive(Debug, Clone)]
pub enum Action {
    /// Param index and param value
    SubmitParam(ton_block::ConfigParamEnum),

    /// Config contract code
    #[allow(unused)]
    UpdateConfigCode(Cell),

    /// New config public key
    UpdateMasterKey(ed25519::PublicKey),

    /// First ref is elector code.
    /// Remaining data is passed to `after_code_upgrade`
    UpdateElectorCode {
        code: Cell,
        params: Option<SliceData>,
    },
}

impl Action {
    fn build(self) -> Result<(u32, BuilderData)> {
        let mut data = BuilderData::new();

        Ok(match self {
            Self::SubmitParam(param) => {
                let index = param.write_to_cell(&mut data)?;
                data.append_u32(index)?;
                (0x43665021, data)
            }
            Self::UpdateConfigCode(code) => {
                data.checked_append_reference(code)?;
                (0x4e436f64, data)
            }
            Self::UpdateMasterKey(key) => {
                data.append_raw(key.as_bytes(), 256).trust_me();
                (0x50624b21, data)
            }
            Self::UpdateElectorCode { code, params } => {
                data.checked_append_reference(code)?;
                if let Some(params) = params {
                    data.append_builder(&BuilderData::from_slice(&params))?;
                }
                (0x4e43ef05, data)
            }
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error("Config does not exist")]
    ConfigNotExists,
    #[error("Invalid config state")]
    InvalidState,
    #[error("Public key mismatch")]
    PublicKeyMismatch,
    #[error("Message expired")]
    MessageExpired,
}

type MessageTx = oneshot::Sender<bool>;
