use std::{borrow::Cow, fmt::Display, time::Duration};

use indicatif::{ProgressBar, ProgressStyle};

pub const OK: &str = "✅";
pub const YES: &str = "👍";
pub const NO: &str = "👎";

pub struct Progress;

impl Progress {
    pub fn section(&self, msg: impl Into<Cow<'static, str>> + Display) -> Section {
        Section::new(msg)
    }
}

pub struct Section {
    progress: ProgressBar,
}

impl Section {
    pub fn new(msg: impl Into<Cow<'static, str>> + Display) -> Self {
        let pb = ProgressBar::new_spinner()
            .with_finish(indicatif::ProgressFinish::AndLeave)
            .with_style(
                ProgressStyle::default_spinner()
                    .template("{spinner} {prefix} {msg}")
                    .expect("template should be valid"),
            );
        pb.enable_steady_tick(Duration::from_millis(100));

        let msg = msg.into();
        if msg.ends_with(':') {
            pb.set_prefix(msg);
        } else {
            pb.set_prefix(format!("{msg}:"));
        }

        Self { progress: pb }
    }

    pub fn update(&self, msg: impl Into<Cow<'static, str>>) {
        self.progress.set_message(msg.into());
    }

    pub fn finish(self, msg: impl Into<Cow<'static, str>>) {
        self.progress.finish_with_message(msg);
    }
}
