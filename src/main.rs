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
}

fn main() {
    let args = Args::parse();

    println!("AWS region: {}", args.aws_region);
    println!("AWS key: {}", args.aws_key_id);
}
