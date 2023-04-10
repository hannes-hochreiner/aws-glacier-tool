use aws_glacier_tool::aws_actions::{archive, vault, AwsActionsError, Config};
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
    Archive {
        filename: String,
        vault: String,
        description: Option<String>,
    },
    /// List all vaults
    ListVaults,
}

#[tokio::main]
async fn main() -> Result<(), AwsActionsError> {
    env_logger::init();

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
        Commands::Archive {
            filename,
            vault,
            description,
        } => {
            let description = description.unwrap_or_default();
            let archive_upload_information =
                archive::upload_file(&config, &filename, &vault, &description).await?;

            println!("{}", serde_json::to_string(&archive_upload_information)?);
        }
    };

    Ok(())
}
