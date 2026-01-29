//! TorChat 2.0 Command-Line Interface
//!
//! A terminal-based chat client for anonymous, encrypted messaging.
//! Identity is automatically generated on first run.

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;

/// TorChat 2.0 - Anonymous, encrypted messaging over Tor
#[derive(Parser)]
#[command(name = "torchat")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Data directory path
    #[arg(short, long, default_value = "~/.torchat")]
    data_dir: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new identity (happens automatically on first run)
    Init {
        /// Force overwrite existing identity
        #[arg(short, long)]
        force: bool,
    },

    /// Show current identity information
    Identity,

    /// Start the TorChat daemon
    Start {
        /// SOCKS5 proxy port
        #[arg(long, default_value = "9050")]
        socks_port: u16,

        /// Tor control port
        #[arg(long, default_value = "9051")]
        control_port: u16,
    },

    /// Add a contact
    Add {
        /// Contact's onion address
        address: String,

        /// Display name for contact
        #[arg(short, long)]
        name: Option<String>,
    },

    /// List contacts
    Contacts,

    /// Send a message
    Send {
        /// Recipient's onion address
        address: String,

        /// Message text
        message: String,
    },

    /// Show chat history with a contact
    History {
        /// Contact's onion address
        address: String,

        /// Number of messages to show
        #[arg(short, long, default_value = "50")]
        limit: u32,
    },

    /// Start a voice call with a contact
    Call {
        /// Contact's onion address
        address: String,
    },

    /// Export identity for backup
    Export {
        /// Output file path
        output: String,
    },

    /// Import identity from backup
    Import {
        /// Input file path
        input: String,
    },

    /// Reset identity (WARNING: destroys current identity!)
    Reset {
        /// Confirm reset
        #[arg(long)]
        confirm: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Expand data directory
    let data_dir = shellexpand::tilde(&cli.data_dir).to_string();

    // If no command specified, show identity (auto-generates if needed)
    let command = cli.command.unwrap_or(Commands::Identity);

    match command {
        Commands::Init { force } => {
            commands::init(&data_dir, force).await?;
        }
        Commands::Identity => {
            commands::show_identity_auto(&data_dir).await?;
        }
        Commands::Start { socks_port, control_port } => {
            commands::start_daemon_auto(&data_dir, socks_port, control_port).await?;
        }
        Commands::Add { address, name } => {
            commands::add_contact_auto(&data_dir, &address, name.as_deref()).await?;
        }
        Commands::Contacts => {
            commands::list_contacts(&data_dir).await?;
        }
        Commands::Send { address, message } => {
            commands::send_message(&data_dir, &address, &message).await?;
        }
        Commands::History { address, limit } => {
            commands::show_history(&data_dir, &address, limit).await?;
        }
        Commands::Call { address } => {
            commands::start_call(&data_dir, &address).await?;
        }
        Commands::Export { output } => {
            commands::export_identity(&data_dir, &output).await?;
        }
        Commands::Import { input } => {
            commands::import_identity(&data_dir, &input).await?;
        }
        Commands::Reset { confirm } => {
            commands::reset_identity(&data_dir, confirm).await?;
        }
    }

    Ok(())
}
