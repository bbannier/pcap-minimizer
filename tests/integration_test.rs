use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::Result;
use pathdiff::diff_paths;

fn check_run(pcap: &Path, test: &Path, output: Option<&Path>) -> Result<Output> {
    let bin = env!("CARGO_BIN_EXE_pcap-minimizer");

    let pcap = pcap.to_string_lossy();
    let test = test.to_string_lossy();
    let output = output.map(|o| o.to_string_lossy());

    let mut args = vec!["-p", &pcap, "-t", &test];
    if let Some(output) = &output {
        args.extend(["-o", output]);
    }

    let output = Command::new(bin).args(args).output()?;
    Ok(output)
}

#[test]
fn example() -> Result<()> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

    let pcap = dir.join("example.pcapng");
    let test = dir.join("get.sh");

    let output = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("output.pcap");
    let _ = fs::remove_file(&output);

    // Minimize the input file. We expect exactly one remaining frame.
    let result = check_run(&pcap, &test, Some(&output))?;
    assert!(result.status.success(), "{result:?}");

    // The output passes the test.
    let status = Command::new("sh").arg(&test).arg(&output).status()?;
    assert!(status.success(), "{status:?}");

    // Running again cannot reduce further and returns an error.
    // Construct a relative test path so we check these code paths as well.
    let test = diff_paths(&test, std::env::current_dir()?).unwrap();
    let result = check_run(&output, &test, None)?;
    assert!(!result.status.success(), "{result:?}");
    let stderr = String::from_utf8(result.stderr)?;
    assert!(
        stderr
            .lines()
            .last()
            .unwrap()
            .contains("could not reduce input"),
        "{stderr}"
    );

    // Validate that we have indeed the intended frame remaining.
    let result = Command::new("tshark").arg("-r").arg(&output).output()?;
    let stdout = String::from_utf8(result.stdout)?;

    // The version of tshark we use in CI only passes the test if it leaves an additional frame in.
    assert!(
        stdout.contains("GET /a") && stdout.lines().count() < 3,
        "{stdout}"
    );

    Ok(())
}
