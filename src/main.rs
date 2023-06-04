use std::io::Read;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use argh::FromArgs;
use everscale_crypto::ed25519;
use nekoton_utils::*;
use ton_block::Serializable;

use self::system_accounts::MultisigType;

mod config;
mod dht;
mod mine;
mod models;
mod system_accounts;
mod zerostate;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let ArgsOrVersion::<App>(app) = argh::from_env::<_>();
    run(app).await
}

async fn run(app: App) -> Result<()> {
    match app.command {
        Subcommand::DhtNode(args) => {
            let secret = hex_or_base64(args.secret.trim())
                .context("Invalid secret key")
                .map(ed25519::SecretKey::from_bytes)?;

            print!("{}", dht::generate_dht_config(args.address, &secret));
            Ok(())
        }
        Subcommand::ZeroState(args) => {
            let config =
                std::fs::read_to_string(args.config).context("Failed to read zerostate config")?;

            if !args.output.is_dir() {
                return Err(anyhow::anyhow!("Expected `output` param to be a directory"));
            }

            print!(
                "{}",
                zerostate::prepare_zerostates(args.output, &config)
                    .context("Failed to prepare zerostates")?
            );
            Ok(())
        }
        Subcommand::Account(args) => {
            let (address, account) = match args.subcommand {
                AccountSubcommand::Giver(args) => {
                    system_accounts::build_giver(args.balance, parse_public_key(args.pubkey)?)
                }
                AccountSubcommand::Multisig(args) => system_accounts::MultisigBuilder::new(
                    parse_public_key(args.pubkey)?,
                    args.multisig_type,
                )
                .custodians(
                    args.custodians
                        .into_iter()
                        .map(parse_public_key)
                        .collect::<Result<Vec<_>>>()?,
                )
                .required_confirms(args.required_confirms)
                .lifetime(args.lifetime)
                .build_with_balance(args.balance),
                AccountSubcommand::Wallet(args) => {
                    system_accounts::build_ever_wallet(args.balance, parse_public_key(args.pubkey)?)
                }
            }
            .context("Failed to build account")?;

            let cell = account.serialize().context("Failed to serialize account")?;
            let boc =
                ton_types::serialize_toc(&cell).context("Failed to serialize account cell")?;

            let json = serde_json::json!({
                "address": address.to_hex_string(),
                "boc": base64::encode(boc),
            });

            print!(
                "{}",
                serde_json::to_string_pretty(&json).expect("Shouldn't fail")
            );
            Ok(())
        }
        Subcommand::KeyPair(_args) => {
            let secret = ed25519::SecretKey::generate(&mut rand::thread_rng());
            let public = ed25519::PublicKey::from(&secret);

            let json = serde_json::json!({
                "secret": hex::encode(secret.as_bytes()),
                "public": hex::encode(public.as_bytes()),
            });

            print!(
                "{}",
                serde_json::to_string_pretty(&json).expect("Shouldn't fail")
            );
            Ok(())
        }
        Subcommand::Config(args) => match args.subcommand {
            CmdConfigSubcommand::Description(_) => {
                print!("{}", config::ParamToChange::description());
                Ok(())
            }
            CmdConfigSubcommand::SetParam(args) => {
                let secret = load_secret_key(args.sign)?;

                let param = serde_json::from_value(serde_json::json!({
                    "param": args.param,
                    "value": args.value,
                }))
                .context("Invalid config param")?;

                config::set_param(args.url, &args.address, &secret, param).await
            }
            CmdConfigSubcommand::SetMasterKey(args) => {
                let secret = load_secret_key(args.sign)?;
                let master_key = parse_public_key(args.pubkey).context("Invalid master key")?;

                config::set_master_key(args.url, &args.address, &secret, master_key).await
            }
            CmdConfigSubcommand::UpdateElector(args) => {
                let secret = load_secret_key(args.sign)?;

                fn parse_cell(cell: &str) -> Result<ton_types::Cell> {
                    let cell = base64::decode(cell)?;
                    ton_types::deserialize_tree_of_cells(&mut cell.as_slice())
                }

                let code = if let Some(code) = args.code {
                    std::fs::read(code).context("Failed to read elector code")?
                } else {
                    let mut code = Vec::new();
                    std::io::stdin()
                        .read_to_end(&mut code)
                        .context("Failed to read elector code from stdin")?;
                    code
                };

                let code = ton_types::deserialize_tree_of_cells(&mut code.as_slice())
                    .context("Invalid elector code")?;
                let params = match args.params {
                    Some(params) => {
                        let cell = parse_cell(&params).context("Invalid params")?;
                        Some(ton_types::SliceData::load_cell(cell)?)
                    }
                    None => None,
                };

                config::set_elector_code(args.url, &args.address, &secret, code, params).await
            }
            CmdConfigSubcommand::ForceKeyBlock(args) => {
                let secret = load_secret_key(args.sign)?;
                let keys = ed25519::KeyPair::from(&secret);

                let action = config::Action::SubmitParam(
                    ton_block::ConfigParamEnum::ConfigParam15(ton_block::ConfigParam15 {
                        validators_elected_for: 900,
                        elections_start_before: 450,
                        elections_end_before: 50,
                        stake_held_for: 450,
                    }),
                );

                let (message, expire_at) = config::create_message(
                    args.seqno,
                    &args.address,
                    action,
                    keys,
                    args.signature_id,
                    args.timeout,
                )
                .context("Failed to create message")?;

                let message = ton_types::serialize_toc(&message.serialize()?)?;

                println!(
                    "{}",
                    serde_json::json!({
                        "boc": base64::encode(message),
                        "expire_at": expire_at,
                    })
                );

                Ok(())
            }
        },
        Subcommand::Mine(args) => mine::mine(
            args.tvc,
            args.abi,
            &args.nonce_field,
            &args.init_data,
            parse_public_key(&args.pubkey).context("Invalid pubkey")?,
            args.target,
            args.token_root,
        ),
    }
}

#[derive(Debug, PartialEq, FromArgs)]
#[argh(description = "Betterscale tools")]
struct App {
    #[argh(subcommand)]
    command: Subcommand,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, FromArgs)]
#[argh(subcommand)]
enum Subcommand {
    DhtNode(CmdDhtNode),
    ZeroState(CmdZeroState),
    Account(CmdAccount),
    KeyPair(CmdKeyPair),
    Config(CmdConfig),
    Mine(CmdMine),
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates DHT node entry
#[argh(subcommand, name = "dhtnode")]
struct CmdDhtNode {
    /// node ADNL socket address
    #[argh(option, long = "address", short = 'a')]
    address: SocketAddrV4,

    /// node ADNL key secret
    #[argh(option, long = "secret", short = 's')]
    secret: String,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates zerostate boc file
#[argh(subcommand, name = "zerostate")]
struct CmdZeroState {
    /// path to the zerostate config
    #[argh(option, long = "config", short = 'c')]
    config: PathBuf,

    /// destination folder path
    #[argh(option, long = "output", short = 'o')]
    output: PathBuf,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Account state creation tools
#[argh(subcommand, name = "account")]
struct CmdAccount {
    #[argh(subcommand)]
    subcommand: AccountSubcommand,
}

#[derive(Debug, PartialEq, FromArgs)]
#[argh(subcommand)]
enum AccountSubcommand {
    Giver(CmdAccountGiver),
    Multisig(CmdAccountMultisig),
    Wallet(CmdAccountWallet),
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates giver account zerostate entry
#[argh(subcommand, name = "giver")]
struct CmdAccountGiver {
    /// account public key
    #[argh(option, long = "pubkey", short = 'p')]
    pubkey: String,

    /// account balance in nano evers
    #[argh(option, long = "balance", short = 'b')]
    balance: u128,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates multisig account zerostate entry
#[argh(subcommand, name = "multisig")]
struct CmdAccountMultisig {
    /// account public key
    #[argh(option, long = "pubkey", short = 'p')]
    pubkey: String,

    /// a list of custodians. `pubkey` is used if no custodians have been specified
    #[argh(option, long = "custodian", short = 'c')]
    custodians: Vec<String>,

    /// number of confirmations required to execute a transaction
    #[argh(option, long = "req-confirms", short = 'r')]
    required_confirms: Option<u8>,

    /// multisig wallet type (multisig2 by default)
    #[argh(
        option,
        long = "type",
        short = 't',
        default = "MultisigType::Multisig2"
    )]
    multisig_type: MultisigType,

    /// custom transaction lifetime in seconds
    #[argh(option, long = "lifetime", short = 'l')]
    lifetime: Option<u32>,

    /// account balance in nano EVER
    #[argh(option, long = "balance", short = 'b')]
    balance: u128,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates ever wallet account zerostate entry
#[argh(subcommand, name = "wallet")]
struct CmdAccountWallet {
    /// account public key
    #[argh(option, long = "pubkey", short = 'p')]
    pubkey: String,

    /// account balance in nano EVER
    #[argh(option, long = "balance", short = 'b')]
    balance: u128,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates ed25519 key pair
#[argh(subcommand, name = "keypair")]
struct CmdKeyPair {}

#[derive(Debug, PartialEq, FromArgs)]
/// Network config tools
#[argh(subcommand, name = "config")]
struct CmdConfig {
    #[argh(subcommand)]
    subcommand: CmdConfigSubcommand,
}

#[derive(Debug, PartialEq, FromArgs)]
#[argh(subcommand)]
enum CmdConfigSubcommand {
    Description(CmdConfigDescription),
    SetParam(CmdConfigSetParam),
    SetMasterKey(CmdConfigSetMasterKey),
    UpdateElector(CmdConfigUpdateElector),
    ForceKeyBlock(CmdConfigForceKeyBlock),
}

#[derive(Debug, PartialEq, FromArgs)]
/// Show params of the config
#[argh(subcommand, name = "description")]
struct CmdConfigDescription {}

#[derive(Debug, PartialEq, FromArgs)]
/// Execute an action to change a config param
#[argh(subcommand, name = "setParam")]
struct CmdConfigSetParam {
    /// config address
    #[argh(
        option,
        long = "address",
        short = 'a',
        default = "default_config_address()"
    )]
    address: ton_block::MsgAddressInt,

    /// gql or jrpc endpoint address
    #[argh(option, long = "url")]
    url: String,

    /// path to the file with keys
    #[argh(option, long = "sign", short = 's')]
    sign: PathBuf,

    /// param name
    #[argh(positional)]
    param: String,

    /// param value
    #[argh(positional)]
    value: serde_json::Value,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Update master public key in the config contract
#[argh(subcommand, name = "setMasterKey")]
struct CmdConfigSetMasterKey {
    /// config address
    #[argh(
        option,
        long = "address",
        short = 'a',
        default = "default_config_address()"
    )]
    address: ton_block::MsgAddressInt,

    /// gql or jrpc endpoint address
    #[argh(option, long = "url")]
    url: String,

    /// path to the file with keys
    #[argh(option, long = "sign", short = 's')]
    sign: PathBuf,

    /// new master public key
    #[argh(positional)]
    pubkey: String,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Update elector code
#[argh(subcommand, name = "updateElector")]
struct CmdConfigUpdateElector {
    /// config address
    #[argh(
        option,
        long = "address",
        short = 'a',
        default = "default_config_address()"
    )]
    address: ton_block::MsgAddressInt,

    /// gql or jrpc endpoint address
    #[argh(option, long = "url")]
    url: String,

    /// path to the file with keys
    #[argh(option, long = "sign", short = 's')]
    sign: PathBuf,

    /// optional additional argument which is passed to the `after_code_upgrade`
    /// as cell slice
    #[argh(option, long = "params", short = 'p')]
    params: Option<String>,

    /// path to the code or empty for input from stdin
    #[argh(positional)]
    code: Option<String>,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Nop update config
#[argh(subcommand, name = "forceKeyBlock")]
struct CmdConfigForceKeyBlock {
    /// config address
    #[argh(
        option,
        long = "address",
        short = 'a',
        default = "default_config_address()"
    )]
    address: ton_block::MsgAddressInt,

    /// config state seqno
    #[argh(option, default = "0")]
    seqno: u32,

    /// path to the file with keys
    #[argh(option, long = "sign", short = 's')]
    sign: PathBuf,

    /// optional signature id
    #[argh(option)]
    signature_id: Option<i32>,

    /// message expiration timeout
    #[argh(option, default = "60")]
    timeout: u32,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates required address for the contract
#[argh(subcommand, name = "mine")]
struct CmdMine {
    /// path to the TVC file
    #[argh(option, long = "tvc")]
    tvc: PathBuf,

    /// path to the ABI file
    #[argh(option, long = "abi")]
    abi: PathBuf,

    /// contract init data value
    #[argh(option, long = "init-data", default = "\"{}\".to_owned()")]
    init_data: String,

    /// nonce field name
    #[argh(option, long = "nonce-field")]
    nonce_field: String,

    /// target address
    #[argh(option, long = "target")]
    target: ton_block::MsgAddressInt,

    /// contract public key (000...000 by default)
    #[argh(option, long = "pubkey", default = "default_pubkey()")]
    pubkey: String,

    /// also mine token address
    #[argh(option, long = "token-root")]
    token_root: Option<ton_block::MsgAddressInt>,
}

fn default_config_address() -> ton_block::MsgAddressInt {
    ton_block::MsgAddressInt::from_str(
        "-1:5555555555555555555555555555555555555555555555555555555555555555",
    )
    .expect("Shouldn't fail")
}

fn default_pubkey() -> String {
    "00".repeat(32)
}

fn load_secret_key(path: PathBuf) -> Result<ed25519::SecretKey> {
    #[derive(serde::Deserialize)]
    struct Content {
        #[serde(with = "serde_hex_array")]
        secret: [u8; 32],
    }
    let data = std::fs::read_to_string(path).context("Failed to load keys")?;
    let Content { secret } = serde_json::from_str(&data).context("Invalid keys")?;
    Ok(ed25519::SecretKey::from_bytes(secret))
}

fn parse_public_key(data: impl AsRef<str>) -> Result<ed25519::PublicKey> {
    hex_or_base64(data.as_ref().trim())
        .ok()
        .and_then(ed25519::PublicKey::from_bytes)
        .context("Invalid public key")
}

fn hex_or_base64<const N: usize>(data: &str) -> Result<[u8; N]> {
    match hex::decode(data) {
        Ok(data) if data.len() == N => Ok(data.try_into().unwrap()),
        _ => match base64::decode(data) {
            Ok(data) if data.len() == N => Ok(data.try_into().unwrap()),
            _ => Err(anyhow::anyhow!("Invalid data")),
        },
    }
}

struct ArgsOrVersion<T: argh::FromArgs>(T);

impl<T: argh::FromArgs> argh::TopLevelCommand for ArgsOrVersion<T> {}

impl<T: argh::FromArgs> argh::FromArgs for ArgsOrVersion<T> {
    fn from_args(command_name: &[&str], args: &[&str]) -> Result<Self, argh::EarlyExit> {
        /// Also use argh for catching `--version`-only invocations
        #[derive(argh::FromArgs)]
        struct Version {
            /// print version information and exit
            #[argh(switch, short = 'v')]
            pub version: bool,
        }

        match Version::from_args(command_name, args) {
            Ok(v) if v.version => Err(argh::EarlyExit {
                output: format!(
                    "{} {}",
                    command_name.first().unwrap_or(&""),
                    env!("CARGO_PKG_VERSION")
                ),
                status: Ok(()),
            }),
            Err(exit) if exit.status.is_ok() => {
                let help = match T::from_args(command_name, &["--help"]) {
                    Ok(_) => unreachable!(),
                    Err(exit) => exit.output,
                };
                Err(argh::EarlyExit {
                    output: format!("{help}  -v, --version     print version information and exit"),
                    status: Ok(()),
                })
            }
            _ => T::from_args(command_name, args).map(Self),
        }
    }
}
