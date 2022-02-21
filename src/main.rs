use std::net::SocketAddrV4;
use std::path::PathBuf;

use anyhow::{Context, Result};
use argh::FromArgs;
use everscale_crypto::ed25519;
use ton_block::Serializable;

mod dht;
mod system_accounts;
mod zerostate;

fn main() {
    if let Err(e) = run(argh::from_env()) {
        eprintln!("{:?}", e);
        std::process::exit(1);
    }
}

fn run(app: App) -> Result<()> {
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
                AccountSubcommand::Giver(args) => system_accounts::build_giver(args.balance),
                AccountSubcommand::Multisig(args) => {
                    let pubkey = hex_or_base64(args.pubkey.trim())
                        .ok()
                        .and_then(ed25519::PublicKey::from_bytes)
                        .context("Invalid public key")?;
                    system_accounts::build_multisig(pubkey, args.balance)
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
    }
}

#[derive(Debug, PartialEq, FromArgs)]
#[argh(description = "Betterscale tools")]
struct App {
    #[argh(subcommand)]
    command: Subcommand,
}

#[derive(Debug, PartialEq, FromArgs)]
#[argh(subcommand)]
enum Subcommand {
    DhtNode(CmdDhtNode),
    ZeroState(CmdZeroState),
    Account(CmdAccount),
    KeyPair(CmdKeyPair),
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
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates giver account zerostate entry
#[argh(subcommand, name = "giver")]
struct CmdAccountGiver {
    /// account balance in nano evers
    #[argh(option, long = "balance", short = 'b')]
    balance: u128,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates multisig account zerostate entry
#[argh(subcommand, name = "multisig")]
struct CmdAccountMultisig {
    /// account public key
    #[argh(option, long = "pubkey", short = 's')]
    pubkey: String,

    /// account balance in nano evers
    #[argh(option, long = "balance", short = 'b')]
    balance: u128,
}

#[derive(Debug, PartialEq, FromArgs)]
/// Generates ed25519 key pair
#[argh(subcommand, name = "keypair")]
struct CmdKeyPair {}

fn hex_or_base64<const N: usize>(data: &str) -> Result<[u8; N]> {
    match hex::decode(data) {
        Ok(data) if data.len() == N => Ok(data.try_into().unwrap()),
        _ => match base64::decode(data) {
            Ok(data) if data.len() == N => Ok(data.try_into().unwrap()),
            _ => Err(anyhow::anyhow!("Invalid data")),
        },
    }
}
