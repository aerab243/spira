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
        #[arg(long, default_value_t = true)]
        kernel: bool,

        #[arg(long, default_value_t = true)]
        services: bool,

        #[arg(short, long, default_value = "terminal")]
        format: String,
    },
    Audit {
        #[arg(short, long, default_value = "terminal")]
        format: String,
    },
    Vulns {
        name: String,
    },
    Update,
}
