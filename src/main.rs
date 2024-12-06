use anyhow::Result;
use clap::Parser;
use pcap_minimizer::minimize;

#[derive(Parser, Debug)]
#[clap(about, version)]
struct Args {
    #[arg(short, long)]
    /// PCAP file to minimize
    pcap: String,

    #[arg(short, long)]
    /// Path to minimized PCAP
    output: Option<String>,

    #[arg(short, long)]
    /// Test command, the input file will be passed as last argument.
    test: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    minimize(&args.pcap, args.output.as_deref(), &args.test)?;

    Ok(())
}
