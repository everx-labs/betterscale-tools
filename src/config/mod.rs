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
use nekoton_utils::{SimpleClock, TrustMe};
use serde::Deserialize;
use tokio::sync::oneshot;
use ton_block::Serializable;
use ton_types::IBitstring;

use crate::zerostate::models::*;

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

#[derive(Deserialize)]
#[serde(
    tag = "param",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum ParamToChange {
    /// Block creation fees
    P14(BlockCreationFees),
    /// Elector params
    P15(ElectorParams),
    /// Validator count
    P16(ValidatorCount),
    /// Stake params
    P17(StakeParams),
    /// Masterchain gas prices
    P20(GasPricesEntry),
    /// Basechain gas prices
    P21(GasPricesEntry),
    /// Masterchain block limits
    P22(BlockLimitsEntry),
    /// Basechain block limits
    P23(BlockLimitsEntry),
    /// Masterchain message forward prices
    P24(MsgForwardPricesEntry),
    /// Basechain message forward prices
    P25(MsgForwardPricesEntry),
}

impl ParamToChange {
    pub fn into_param(self) -> Result<ton_block::ConfigParamEnum> {
        use ton_block::ConfigParamEnum;

        Ok(match self {
            Self::P14(v) => ConfigParamEnum::ConfigParam14(v.build()),
            Self::P15(v) => ConfigParamEnum::ConfigParam15(v.build()),
            Self::P16(v) => ConfigParamEnum::ConfigParam16(v.build()),
            Self::P17(v) => ConfigParamEnum::ConfigParam17(v.build()),
            Self::P20(v) => ConfigParamEnum::ConfigParam20(v.build()),
            Self::P21(v) => ConfigParamEnum::ConfigParam21(v.build()),
            Self::P22(v) => ConfigParamEnum::ConfigParam22(v.build()?),
            Self::P23(v) => ConfigParamEnum::ConfigParam23(v.build()?),
            Self::P24(v) => ConfigParamEnum::ConfigParam24(v.build()),
            Self::P25(v) => ConfigParamEnum::ConfigParam25(v.build()),
        })
    }
}

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
            GenericContract::subscribe(clock, transport.clone(), address.clone(), handler.clone())
                .await
                .context("Failed to create config contract subscription")?,
        ));

        tokio::spawn({
            let subscription = subscription.clone();
            async move {
                loop {
                    if let Err(e) = subscription.lock().await.refresh().await {
                        eprintln!("Failed to update config subscription: {:?}", e);
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
        let seqno = self
            .check_state(Some(ed25519::PublicKey::from(secret)))
            .await?;

        let (message, expire_at) =
            create_message(seqno, &self.address, action, ed25519::KeyPair::from(secret))
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
            RawContractState::NotExists => return Err(ConfigError::ConfigNotExists.into()),
        };

        let mut data: ton_types::SliceData = match config_state.storage.state {
            ton_block::AccountState::AccountActive { state_init, .. } => state_init.data,
            _ => None,
        }
        .ok_or(ConfigError::InvalidState)?
        .into();

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

fn create_message(
    seqno: u32,
    address: &ton_block::MsgAddressInt,
    action: Action,
    keys: ed25519::KeyPair,
) -> Result<(ton_block::Message, u32)> {
    let (action, data) = action.build().context("Failed to build action")?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .trust_me()
        .as_secs() as u32;
    let expire_at = now + 60;

    let mut builder = ton_types::BuilderData::new();
    builder
        .append_u32(action)? // action
        .append_u32(seqno)? // msg_seqno
        .append_u32(expire_at)? // valid_until
        .append_builder(&data)?; // action data

    let hash = builder.clone().into_cell()?.repr_hash();
    let signature = keys.sign_raw(hash.as_slice());
    builder.prepend_raw(&signature, 512)?;

    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst: address.clone(),
            ..Default::default()
        });
    *message.body_mut() = Some(builder.into());

    Ok((message, expire_at))
}

fn make_client(url: String) -> Result<Arc<dyn Transport>> {
    let client = GqlClient::new(GqlNetworkSettings {
        endpoints: vec![url],
        latency_detection_interval: Duration::from_secs(1),
        ..Default::default()
    })?;

    Ok(Arc::new(nekoton::transport::gql::GqlTransport::new(client)))
}

#[derive(Debug, Clone)]
enum Action {
    /// Param index and param value
    SubmitParam(ton_block::ConfigParamEnum),

    /// Config contract code
    #[allow(unused)]
    UpdateConfigCode(ton_types::Cell),

    /// New config public key
    UpdateMasterKey(ed25519::PublicKey),

    /// First ref is elector code.
    /// Remaining data is passed to `after_code_upgrade`
    #[allow(unused)]
    UpdateElectorCode(ton_types::SliceData),
}

impl Action {
    fn build(self) -> Result<(u32, ton_types::BuilderData)> {
        let mut data = ton_types::BuilderData::new();

        Ok(match self {
            Self::SubmitParam(param) => {
                let index = param.write_to_cell(&mut data)?;
                data.append_u32(index)?;
                (0x43665021, data)
            }
            Self::UpdateConfigCode(code) => {
                data.append_reference_cell(code);
                (0x4e436f64, data)
            }
            Self::UpdateMasterKey(key) => {
                data.append_raw(key.as_bytes(), 256).trust_me();
                (0x50624b21, data)
            }
            Self::UpdateElectorCode(code_with_params) => {
                (0x4e43ef05, code_with_params.into_cell().into())
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
