use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Parser;
use pcap_minimizer::{MinimizationPass, Passes, Test, minimize};

#[derive(Parser, Debug)]
#[clap(about, version)]
struct Args {
    #[arg(short, long)]
    /// PCAP file to minimize
    pcap: Utf8PathBuf,

    #[arg(short, long)]
    /// Path to minimized PCAP
    output: Option<Utf8PathBuf>,

    #[arg(short, long)]
    /// Test script, the input file will be passed as last argument.
    test: Test,

    /// Minimization passes to skip, separate multiple passes by ','.
    #[arg(short, long, value_delimiter = ',')]
    skip_passes: Vec<MinimizationPass>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let passes = Passes::skipping(&args.skip_passes);

    minimize(args.pcap, args.output.as_ref(), &args.test, &passes)?;

    Ok(())
}
