pub mod progress;

use std::{cmp, ops::Range, process::Command};

use camino::{Utf8Path, Utf8PathBuf};
use progress::{Progress, NO, OK, YES};

use bisector::{Bisector, ConvergeTo, Indices, Step};
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Test(String);

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

impl From<String> for Test {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[derive(Debug, PartialEq)]
struct Summary {
    num_flows: usize,
    num_frames: usize,
}

#[derive(Debug, Error)]
pub enum PcapError {
    #[error("cannot convert filename to UTF-8")]
    PathNotUtf8,

    #[error("I/O error")]
    IoError(std::io::Error),

    #[error("test does not pass for initial input")]
    TestError,

    #[error("minimization produced file not passing test")]
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

        let p = progress.section(format!(
            "dropping random {}s",
            match kind {
                DropKind::Flow => "flow",
                DropKind::Frame => "frame",
            }
        ));

        let mut filtered = self.try_clone()?;
        let mut num_removed = 0;

        let filter_quantity = match kind {
            DropKind::Flow => "tcp.stream",
            DropKind::Frame => "frame.number",
        };

        let value_max = match kind {
            DropKind::Flow => stats.num_flows,
            DropKind::Frame => stats.num_frames,
        };

        if value_max == 0 {
            p.update("already minimal");
        } else {
            for frame in (0..value_max).rev() {
                p.update(format!("{num_removed}/{value_max} removed"));

                let chopped = filtered.filter(&format!("{filter_quantity} != {frame}"))?;

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
            input.filter("tcp")?
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

    fn filter(&self, filter: &str) -> Result<Self, PcapError> {
        assert!(!filter.is_empty(), "filter must not be empty");

        let output = Pcap::new()?;

        rtshark::RTSharkBuilder::builder()
            .input_path(self.path().as_str())
            .display_filter(filter)
            .output_path(output.path().as_str())
            .batch()
            .map_err(PcapError::IoError)?;

        Ok(output)
    }

    fn trim_ends(
        &self,
        value: &str,
        range: Range<usize>,
        test: &Test,
        progress: &Progress,
    ) -> Result<Option<Pcap>, PcapError> {
        enum Side {
            Left,
            Right,
        }

        impl Side {
            fn converge(
                &self,
                x: usize,
                filter: &str,
                test: &Test,
                pcap: &Pcap,
            ) -> Result<ConvergeTo<usize, usize>, PcapError> {
                let chopped = pcap.filter(filter)?;

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
                value: &str,
                mut start: usize,
                mut end: usize,
                test: &Test,
                pcap: &Pcap,
                progress: &Progress,
            ) -> (usize, usize) {
                let side = match self {
                    Side::Right => "last",
                    Side::Left => "first",
                };

                let p = progress.section(format!("bisecting {side} {value}"));
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
                            Side::Right => format!("{value} < {x}"),
                            Side::Left => format!("{x} < {value}"),
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
            Ok(Some(self.filter(&format!(
                "{start} <= {value} && {value} <= {end}"
            ))?))
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
) -> Result<(), PcapError> {
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

    if let Some(f) = input.filter_tcp(test, Some(&stats), &progress)? {
        input = f;
    }

    if stats.num_flows > 0 {
        let Some(f) = input.trim_ends("tcp.stream", 0..stats.num_flows, test, &progress)? else {
            return Ok(());
        };
        input = f;
    }

    let Summary { num_frames, .. } = input.summary()?;
    if let Some(f) = input.trim_ends("frame.number", 0..num_frames, test, &progress)? {
        input = f;
    };

    if let Some(f) = input.drop_any(DropKind::Flow, test, &progress)? {
        input = f;
    }
    if let Some(f) = input.drop_any(DropKind::Frame, test, &progress)? {
        input = f;
    }

    {
        let p = progress.section("reduced statistics");
        let Summary { num_frames, .. } = input.summary()?;
        p.update(format!("{num_frames} frames"));
    }

    {
        let p = progress.section(
            "checking that minimized file still passes test to deal with foresterre/bisector#3",
        );
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
