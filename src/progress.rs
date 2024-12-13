use std::{borrow::Cow, fmt::Display, time::Duration};

use indicatif::{ProgressBar, ProgressStyle};

pub const OK: &str = "✅";
pub const YES: &str = "👍";
pub const NO: &str = "👎";

pub struct Progress;

impl Progress {
    pub fn section(&self, msg: impl Into<Cow<'static, str>> + Display) -> Section {
        Section::new(msg, None)
    }

    pub fn section_with_length(
        &self,
        msg: impl Into<Cow<'static, str>> + Display,
        len: u64,
    ) -> Section {
        Section::new(msg, Some(len))
    }
}

pub struct Section {
    progress: ProgressBar,
}

impl Section {
    const STYLE: &str = "{spinner} {prefix} {msg}";
    const STYLE_WITH_BAR: &str = "{spinner} {prefix} {msg} {bar}";

    pub fn new(msg: impl Into<Cow<'static, str>> + Display, len: Option<u64>) -> Self {
        let pb = ProgressBar::new_spinner()
            .with_finish(indicatif::ProgressFinish::AndLeave)
            .with_style(
                ProgressStyle::default_spinner()
                    .template(if len.is_some() {
                        Self::STYLE_WITH_BAR
                    } else {
                        Self::STYLE
                    })
                    .expect("template should be valid"),
            );
        pb.enable_steady_tick(Duration::from_millis(100));

        let msg = msg.into();
        if msg.ends_with(':') {
            pb.set_prefix(msg);
        } else {
            pb.set_prefix(format!("{msg}:"));
        }

        if let Some(len) = len {
            pb.set_length(len);
        }

        Self { progress: pb }
    }

    pub fn update(&self, msg: impl Into<Cow<'static, str>>) {
        self.progress.set_message(msg.into());
    }

    pub fn update_value_with_msg(&self, value: u64, msg: impl Into<Cow<'static, str>>) {
        self.progress.set_position(value);
        self.update(msg);
    }

    pub fn finish(self, msg: impl Into<Cow<'static, str>>) {
        self.progress.finish_with_message(msg);
    }
}
