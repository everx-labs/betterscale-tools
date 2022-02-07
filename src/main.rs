use std::net::SocketAddrV4;
use std::path::PathBuf;

use anyhow::{Context, Result};
use argh::FromArgs;

mod dht;
mod ed25519;
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

fn hex_or_base64<const N: usize>(data: &str) -> Result<[u8; N]> {
    match hex::decode(data) {
        Ok(data) if data.len() == N => Ok(data.try_into().unwrap()),
        _ => match base64::decode(data) {
            Ok(data) if data.len() == N => Ok(data.try_into().unwrap()),
            _ => Err(anyhow::anyhow!("Invalid data")),
        },
    }
}
