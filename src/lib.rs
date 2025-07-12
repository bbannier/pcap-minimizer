pub mod progress;

use std::{cmp, fmt::Display, ops::Range, process::Command, str::FromStr};

use camino::{Utf8Path, Utf8PathBuf};
use clap::ValueEnum;
use progress::{NO, OK, Progress, YES};

use bisector::{Bisector, ConvergeTo, Indices, Step};
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
pub enum MinimizationPass {
    BisectFlow,
    BisectFrame,
    DropFlow,
    DropFrame,
}

struct Passes<'v>(Option<&'v Vec<MinimizationPass>>);

impl Passes<'_> {
    pub fn has(&self, opt: MinimizationPass) -> bool {
        !self.0.is_some_and(|opts| opts.contains(&opt))
    }
}

#[derive(Debug, Clone)]
pub struct Test(Utf8PathBuf);

impl Test {
    fn passes_with(&self, pcap: &Pcap) -> Result<bool, PcapError> {
        let cmd = format!("{test} {input}", test = &self.0, input = pcap.path());
        let output = Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .map_err(PcapError::IoError)?;
        Ok(output.status.success())
    }
}

impl FromStr for Test {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = Utf8PathBuf::from(s);

        let path = if path.is_relative() {
            let path = path.as_std_path().canonicalize()?;
            Utf8PathBuf::try_from(path).map_err(camino::FromPathBufError::into_io_error)?
        } else {
            path
        };

        Ok(Self(path))
    }
}

struct Filter(String);

impl Filter {
    fn apply(&self, pcap: &Pcap) -> Result<Pcap, PcapError> {
        let output = Pcap::new()?;

        rtshark::RTSharkBuilder::builder()
            .input_path(pcap.path().as_str())
            .display_filter(&self.0)
            .output_path(output.path().as_str())
            .batch()
            .map_err(PcapError::IoError)?;

        Ok(output)
    }
}

macro_rules! filter {
    ($f:literal) => {{
        assert!(!$f.is_empty(), "filter must not be empty");
        Filter(format!($f))
    }};
}

macro_rules! filter_apply {
    ($pcap:expr_2021, $f:literal) => {{
        let filter = filter!($f);
        filter.apply($pcap)
    }};
    ($pcap:expr_2021, $f:expr_2021) => {
        $f.apply($pcap)
    };
}

#[derive(Debug)]
enum Value {
    FrameNumber,
    TcpStream,
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::FrameNumber => "frame.number".fmt(f),
            Value::TcpStream => "tcp.stream".fmt(f),
        }
    }
}

#[derive(Debug, PartialEq)]
struct Summary {
    num_flows: u64,
    num_frames: u64,
}

#[derive(Debug, Error)]
pub enum PcapError {
    #[error("cannot convert filename to UTF-8")]
    PathNotUtf8,

    #[error("I/O error")]
    IoError(std::io::Error),

    #[error("test does not pass for initial input")]
    TestError,

    #[error(
        "minimization produced file not passing test, consider skipping bisecting passes with '-s'"
    )]
    // We should only really get here if bisecting produced non-sensical results due to
    // https://github.com/foresterre/bisector/issues/3.
    MinimizationError,
}

enum Pcap {
    Owned(NamedTempFile, Utf8PathBuf),
    Ref(Utf8PathBuf),
}

impl Pcap {
    fn new() -> std::result::Result<Self, PcapError> {
        let f = NamedTempFile::new().map_err(PcapError::IoError)?;
        let p = f
            .path()
            .to_path_buf()
            .try_into()
            .map_err(|_| PcapError::PathNotUtf8)?;
        Ok(Pcap::Owned(f, p))
    }

    fn path(&self) -> &Utf8Path {
        match self {
            Pcap::Owned(_, p) => p,
            Pcap::Ref(f) => f,
        }
    }

    fn save<P>(self, new_path: P) -> std::result::Result<(), PcapError>
    where
        P: AsRef<std::path::Path>,
    {
        match self {
            Pcap::Owned(f, _) => {
                f.persist(new_path.as_ref())
                    .map_err(|e| PcapError::IoError(e.error))?;
            }
            Pcap::Ref(f) => {
                std::fs::copy(f, new_path).map_err(PcapError::IoError)?;
            }
        }

        Ok(())
    }

    fn drop_any(
        &self,
        kind: DropKind,
        test: &Test,
        progress: &Progress,
    ) -> Result<Option<Pcap>, PcapError> {
        let stats = self.summary()?;

        let p = progress.section_with_length(
            format!(
                "dropping consecutive {}s",
                match kind {
                    DropKind::Flow => "flow",
                    DropKind::Frame => "frame",
                }
            ),
            match kind {
                DropKind::Flow => stats.num_flows,
                DropKind::Frame => stats.num_frames,
            },
        );

        let mut filtered = self.try_clone()?;
        let mut num_removed = 0;

        let filter_quantity = match kind {
            DropKind::Flow => "tcp.stream",
            DropKind::Frame => "frame.number",
        };

        let value_max = match kind {
            DropKind::Flow => stats.num_flows + 1, // tshark numbers flows starting with zero.
            DropKind::Frame => stats.num_frames,
        };

        if value_max == 0 {
            p.update("already minimal");
        } else {
            for x in (0..value_max).rev() {
                p.update_value_with_msg(
                    value_max - x,
                    format!("{num_removed}/{value_max} removed"),
                );

                let chopped = filter_apply!(&filtered, "{filter_quantity} != {x}")?;

                if test.passes_with(&chopped)? {
                    filtered = chopped;
                    num_removed += 1;
                }
            }
        }

        Ok(if stats == filtered.summary()? {
            None
        } else {
            Some(filtered)
        })
    }

    fn filter_tcp(
        &self,
        test: &Test,
        stats: Option<&Summary>,
        progress: &Progress,
    ) -> Result<Option<Self>, PcapError> {
        let stats = match stats {
            Some(s) => s,
            None => &self.summary()?,
        };

        let p = progress.section("checking whether test reproduces with only TCP traffic");

        let input = self.try_clone()?;

        let input = if stats.num_flows > 0 {
            filter_apply!(&input, "tcp")?
        } else {
            input
        };

        if test.passes_with(&input)? {
            p.update(YES);
            Ok(Some(input))
        } else {
            p.update(NO);
            Ok(None)
        }
    }

    fn trim_ends(
        &self,
        value: &Value,
        range: Range<u64>,
        test: &Test,
        progress: &Progress,
    ) -> Result<Option<Pcap>, PcapError> {
        enum Side {
            Left,
            Right,
        }

        impl Display for Side {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Side::Left => "first".fmt(f),
                    Side::Right => "last".fmt(f),
                }
            }
        }

        impl Side {
            fn converge(
                &self,
                x: u64,
                filter: &Filter,
                test: &Test,
                pcap: &Pcap,
            ) -> Result<ConvergeTo<u64, u64>, PcapError> {
                let chopped = filter.apply(pcap)?;

                if test.passes_with(&chopped)? {
                    match self {
                        Side::Right => Ok(ConvergeTo::Left(x)),
                        Side::Left => Ok(ConvergeTo::Right(x)),
                    }
                } else {
                    match self {
                        Side::Left => Ok(ConvergeTo::Left(x)),
                        Side::Right => Ok(ConvergeTo::Right(x)),
                    }
                }
            }

            fn bisect(
                &self,
                value: &Value,
                mut start: u64,
                mut end: u64,
                test: &Test,
                pcap: &Pcap,
                progress: &Progress,
            ) -> (u64, u64) {
                let p = progress.section(format!("bisecting {self} {value}"));
                p.update(format!("[{start}...{end}]"));

                let values: Vec<_> = (start..=end).collect();
                let bisector = Bisector::new(values.as_slice());
                let mut i = Indices::from_bisector(&bisector);
                while let Ok(Step {
                    indices,
                    result: Some(t),
                }) = bisector.try_bisect(
                    |&x| {
                        let filter = match self {
                            Side::Right => filter!("{value} < {x}"),
                            Side::Left => filter!("{x} < {value}"),
                        };

                        self.converge(x, &filter, test, pcap)
                    },
                    i,
                ) {
                    i = indices;

                    // Depending on the side we converge from only update the start and end if
                    // the convergence function indicated that the tested value was in the good
                    // range.
                    p.update(format!("[{start}...{end}]"));

                    match self {
                        Side::Left => {
                            if let ConvergeTo::Right(x) = t {
                                start = x;
                            }
                        }
                        Side::Right => {
                            if let ConvergeTo::Left(x) = t {
                                end = x;
                            }
                        }
                    }

                    p.update(format!("[{start}...{end}]"));
                }

                p.update(OK);

                (start, end)
            }
        }

        let mut start = range.start;
        let mut end = range.end;

        for side in [Side::Right, Side::Left] {
            (start, end) = side.bisect(value, start, end, test, self, progress);
        }

        if (start..end) == range {
            Ok(None)
        } else {
            Ok(Some(filter_apply!(
                self,
                "{start} <= {value} && {value} <= {end}"
            )?))
        }
    }

    fn summary(&self) -> Result<Summary, PcapError> {
        let mut s = rtshark::RTSharkBuilder::builder()
            .input_path(self.path().as_str())
            .metadata_whitelist("tcp.stream")
            .spawn()
            .map_err(PcapError::IoError)?;

        let mut num_flows = 0;
        let mut num_frames = 0;

        loop {
            let Some(p) = s.read().map_err(PcapError::IoError)? else {
                break;
            };

            num_frames += 1;

            if let Some(tcp_stream) = p.layer_name("tcp").and_then(|l| {
                l.metadata("tcp.stream")
                    .and_then(|m| m.value().parse().ok())
            }) {
                num_flows = cmp::max(tcp_stream, num_flows);
            }
        }

        Ok(Summary {
            num_flows,
            num_frames,
        })
    }

    fn try_clone(&self) -> Result<Self, PcapError> {
        match &self {
            Pcap::Owned(f, _) => {
                let new = NamedTempFile::new().map_err(PcapError::IoError)?;
                let new_path = new
                    .path()
                    .to_path_buf()
                    .try_into()
                    .map_err(|_| PcapError::PathNotUtf8)?;

                std::fs::copy(f, new.path()).map_err(PcapError::IoError)?;
                Ok(Pcap::Owned(new, new_path))
            }
            Pcap::Ref(f) => Ok(Pcap::Ref(f.clone())),
        }
    }
}

impl From<Utf8PathBuf> for Pcap {
    fn from(value: Utf8PathBuf) -> Self {
        Self::Ref(value)
    }
}

#[derive(Clone, Copy)]
enum DropKind {
    Frame,
    Flow,
}

pub fn minimize(
    input: Utf8PathBuf,
    output: Option<&Utf8PathBuf>,
    test: &Test,
    options: Option<&Vec<MinimizationPass>>,
) -> Result<(), PcapError> {
    let options = Passes(options);

    let progress = Progress;

    let mut input = Pcap::from(input);

    {
        let p = progress.section("checking whether test fails for input file");
        if !test.passes_with(&input)? {
            p.finish(NO);
            return Err(PcapError::TestError);
        }
        p.update(YES);
    }

    let stats: Summary;
    {
        let p = progress.section("gathering statistics");
        stats = input.summary()?;
        p.finish(format!(
            "reducing {frames} frames in {flows} TCP flows",
            frames = stats.num_frames,
            flows = stats.num_flows
        ));
    }

    // Operating on TCP flows only makes sense if the test passes with only TCP.
    let tcp_only = match input.filter_tcp(test, Some(&stats), &progress)? {
        Some(f) => {
            input = f;
            true
        }
        _ => false,
    };

    if tcp_only && options.has(MinimizationPass::BisectFlow) && stats.num_flows > 0 {
        if let Some(f) = input.trim_ends(&Value::TcpStream, 0..stats.num_flows, test, &progress)? {
            input = f;
        }
    }

    if options.has(MinimizationPass::BisectFrame) {
        let Summary { num_frames, .. } = input.summary()?;
        // tshark numbers frames starting from 1. Still include zero so we can handle them changing
        // their indexing.
        #[allow(clippy::range_plus_one)]
        if let Some(f) = input.trim_ends(&Value::FrameNumber, 0..num_frames + 1, test, &progress)? {
            input = f;
        }
    }

    if tcp_only && options.has(MinimizationPass::DropFlow) {
        if let Some(f) = input.drop_any(DropKind::Flow, test, &progress)? {
            input = f;
        }
    }
    if options.has(MinimizationPass::DropFrame) {
        if let Some(f) = input.drop_any(DropKind::Frame, test, &progress)? {
            input = f;
        }
    }

    {
        let p = progress.section("reduced statistics");
        let Summary { num_frames, .. } = input.summary()?;
        p.update(format!("{num_frames} frames"));
    }

    {
        let p = progress.section("checking that minimized file still passes test");
        if !test.passes_with(&input)? {
            p.update(NO);
            return Err(PcapError::MinimizationError);
        }
        p.update(YES);
    }

    if let Some(output) = output {
        input.save(output)?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::Passes;

    #[test]
    fn pass_has_default() {
        // By default all passes should be enabled.
        let xs = Passes(None);
        assert!(xs.has(crate::MinimizationPass::DropFlow));
    }

    #[test]
    fn pass_has_disabled() {
        let disabled_passes = vec![crate::MinimizationPass::DropFlow];
        let xs = Passes(Some(&disabled_passes));

        assert!(!xs.has(crate::MinimizationPass::DropFlow));
        assert!(xs.has(crate::MinimizationPass::BisectFlow));
    }
}
