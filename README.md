# pcap-minimizer

A [tshark](https://tshark.dev) frontend performing some minimization of PCAP files
according to a user-defined test.

## Synopsis

```prose
Usage: pcap-minimizer [OPTIONS] --pcap <PCAP> --test <TEST>

Options:
  -p, --pcap <PCAP>                PCAP file to minimize
  -o, --output <OUTPUT>            Path to minimized PCAP
  -t, --test <TEST>                Test command, the input file will be passed as last argument
  -s, --skip-passes <SKIP_PASSES>  Minimization passes to skip, separate multiple passes by ',' [possible values: bisect-flow, bisect-frame, drop-flow, drop-frame]
  -h, --help                       Print help
  -V, --version                    Print version
```

## Implementation

Given a test script and a PCAP file this tool will repeatedly remove frames
while still making sure that the test command passes. The test command should
return `0` if the input file is interesting. The minimizer passes the input
file as last argument.

An example test command would be `--test ./test.sh` referencing an executable shell
script in the current directory:

```sh
#!/usr/bin/env bash

set -eu

# In this case the minimizes passes the input file as first argument, $1.
FILESIZE=$(du "$1" | cut -f1)

# Test passes if the input file is larger than 10 blocks.
[[ $FILESIZE > 10 ]]
```

The minimizer implements the following passes, in order:

- for a given list of TCP flows, remove flows appearing first and last (pass `bisect-flow`)
- trim frames at the start and end of the PCAP (pass `bisect-frame`)
- try to drop individual TCP flows, starting from the beginning (pass `drop-flow`)
- try to drop individual packets, starting from the beginning (pass `drop-frame`)

> [!NOTE]
> Since the dropping steps can be expensive only a single pass over the data is
> done. This means that running the minimizer again might reduce the data
> further.

The general idea is that many test cases trigger on a small number of TCP
flows, or on a small number of frames relatively close together. The passes
doing trimming via bisection can quickly reduce the number of frames in the
input, so that the computationally more expense consecutive flow/frame dropping
steps have less input to work with.

> [!WARNING]
> Currently the bisection algorithm can produce output not passing the test
> anymore; at the end of the minimization a test for this internal error is
> performed. If your input triggers this error try disabling one or more
> bisection steps via `--skip-passes`.

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
