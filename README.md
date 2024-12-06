# pcap-minimizer

A [tshark](https://tshark.dev) frontend performing some minimization of PCAP files
according to a user-defined test.

## Synopsis

```prose
Usage: pcap-minimizer [OPTIONS] --pcap <PCAP> --test <TEST>

Options:
  -p, --pcap <PCAP>      PCAP file to minimize
  -o, --output <OUTPUT>  Path to minimized PCAP
  -t, --test <TEST>      Test command, the input file will be passed as last argument
  -h, --help             Print help
  -V, --version          Print version
```

## Installation

`tshark` is required and needs to be in `PATH`, see [their
documentation](https://tshark.dev/setup/install/#installing-tshark-only).

Download and install the binary for the target platform from the [latest
release](https://github.com/bbannier/pcap-minimizer/releases/latest).

### Building from source

If needed install a Rust toolchain, e.g., with [`rustup`](https://rustup.rs/).

```console
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install project from this repository.

```console
cargo install --locked --git https://github.com/bbannier/pcap-minimizer
```

## Implementation

Given a test script and a PCAP file this tool will repeatedly remove frames
while still making sure that the test script passes. We implement the following minimizations:

- trim frames at the start and end of the PCAP
- for a given list of TCP flows, remove flows appearing first and last

We make no attempts to remove packets in the middle of the
interesting range (beyond possible removal of packages from interspersed
flows), but often inputs can still be reduced significantly (especially if the
test triggers for TCP traffic).
