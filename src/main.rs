use aws_glacier_tool::aws_actions::{vault, AwsActionsError, Config};
use clap::{Parser, Subcommand};

/// Tool to archive and retrieve files using AWS glacier
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// AWS region
    #[arg(long, env)]
    aws_region: String,

    /// AWS secret key
    #[arg(long, env)]
    aws_secret_key: String,

    /// AWS key id
    #[arg(long, env)]
    aws_key_id: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Name of the file to archive
    Archive { filename: String },
    /// List all vaults
    ListVaults,
}

#[tokio::main]
async fn main() -> Result<(), AwsActionsError> {
    let args = Args::parse();
    let config = Config {
        region: args.aws_region,
        secret_key: args.aws_secret_key,
        key_id: args.aws_key_id,
    };

    match args.command {
        Commands::ListVaults => {
            let vault_list = vault::list_vaults(&config).await?;

            println!("{}", serde_json::to_string(&vault_list)?)
        }
        Commands::Archive { filename: _ } => {
            todo!()
        }
    };

    Ok(())
}
