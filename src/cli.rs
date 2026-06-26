use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "spira")]
#[command(about = "Outil d'analyse de vulnérabilités pour systèmes Linux")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, global = true)]
    pub output: Option<String>,

    #[arg(long, global = true)]
    pub offline: bool,

    #[arg(short, long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    Detect {
        #[arg(long)]
        kernel: bool,

        #[arg(long)]
        packages: bool,
    },
    Packages,
    Scan {
        #[arg(long)]
        kernel: bool,

        #[arg(long)]
        services: bool,
    },
    Audit,
    Vulns {
        name: String,
    },
    Update,
}
