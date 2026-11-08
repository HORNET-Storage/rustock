//! `--import-blocks` against blocks rskj mined.
//!
//! `fixtures/rskj-regtest-ecdsa-1-15.txt.gz` is blocks 1 to 15 of a chain rskj's
//! regtest mined from `fixtures/rskj-regtest-genesis.json`, as rskj's
//! `ExportBlocks` writes them: version-2 headers, twenty contract calls a
//! block, a flush at block 10 and REMASC's first payout at block 15, which
//! pays rskj's regtest federation.

use std::path::Path;
use std::process::Command;

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn import(blocks: &Path, dir: &Path) -> std::process::Output {
    import_command(blocks, dir)
        .output()
        .expect("rustock-cli runs")
}

fn import_command(blocks: &Path, dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustock-cli"));
    cmd.args(["--network-id", "33", "--no-rpc", "--log-to-stdout"])
        .arg("--data-dir")
        .arg(dir.join("db"))
        .args(["--trie-backend", "external", "--trie-dir"])
        .arg(dir.join("trie"))
        .arg("--genesis")
        .arg(Path::new(DATA).join("rskj-regtest-genesis.json"))
        .args(["--skip-pow-validation", "--consensus-rule", "rskip97=0"])
        .args([
            "--min-gas-limit",
            "3000000",
            "--max-gas-limit",
            "18446744073709551615",
        ])
        .arg("--import-blocks")
        .arg(blocks);
    cmd
}

#[test]
fn imports_rskj_regtest_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let out = import(
        &Path::new(DATA).join("rskj-regtest-ecdsa-1-15.txt.gz"),
        dir.path(),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "import failed:\n{stdout}\n{stderr}");
    // The best block is rskj's block 15.
    assert!(stdout.contains("Imported 15 blocks"), "{stdout}");
    assert!(
        stdout.contains(
            "best block #15 0xc06f0fa7bd7aae0c0c3066bf2c5b8e5fb8eea326238a67f5bbdf338221cae448"
        ),
        "{stdout}"
    );
}

#[test]
fn the_breakdown_log_has_a_line_per_block() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("logs").join("block-breakdown.log");
    let mut cmd = import_command(
        &Path::new(DATA).join("rskj-regtest-ecdsa-1-15.txt.gz"),
        dir.path(),
    );
    let out = cmd.arg("--breakdown-log").arg(&log).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 15);
    for (i, line) in lines.iter().enumerate() {
        let prefix = format!("block connect breakdown best: block={} hash=", i + 1);
        assert!(line.starts_with(&prefix), "{line}");
        for key in [
            "totalMs=",
            "preambleMs=",
            "initialValidationMs=",
            "executeMs=",
            "trieSaveMs=",
            "postExecuteValidationMs=",
            "switchChainMs=",
            "saveReceiptsMs=",
            "onBestBlockMs=",
            "txCount=",
            "gasUsed=",
        ] {
            assert!(line.contains(key), "{key} missing: {line}");
        }
    }
    assert!(lines[14]
        .contains("hash=c06f0fa7bd7aae0c0c3066bf2c5b8e5fb8eea326238a67f5bbdf338221cae448 "));
    assert!(lines[14].contains(" txCount=21 "));
}

#[test]
fn a_block_that_does_not_connect_stops_the_import() {
    use std::io::{BufRead, Write};
    let dir = tempfile::tempdir().unwrap();
    // Block 2 onwards: block 2's parent is not genesis.
    let file = std::fs::File::open(Path::new(DATA).join("rskj-regtest-ecdsa-1-15.txt.gz")).unwrap();
    let lines: Vec<String> = std::io::BufReader::new(flate2::read::GzDecoder::new(file))
        .lines()
        .map(Result::unwrap)
        .collect();
    let path = dir.path().join("from-2.txt");
    let mut out = std::fs::File::create(&path).unwrap();
    for line in &lines[1..3] {
        writeln!(out, "{line}").unwrap();
    }
    drop(out);

    let out = import(&path, dir.path());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("import failed at block 2 hash "),
        "{stderr}"
    );
    assert!(stderr.contains("check parent"), "{stderr}");
}

/// `--export-blocks` after an import reproduces rskj's file byte for byte:
/// the hash, the total difficulty and rskj's full block encoding, versioned
/// headers included. A range writes only that range.
#[test]
fn an_export_after_an_import_reproduces_rskjs_file() {
    use std::io::Read;

    let dir = tempfile::tempdir().unwrap();
    let fixture = Path::new(DATA).join("rskj-regtest-ecdsa-1-15.txt.gz");
    let out = import(&fixture, dir.path());
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let mut expected = String::new();
    flate2::read::MultiGzDecoder::new(std::fs::File::open(&fixture).unwrap())
        .read_to_string(&mut expected)
        .unwrap();
    let expected: Vec<&str> = expected.lines().collect();
    assert_eq!(expected.len(), 15);

    let export = |from: &str, to: Option<&str>, name: &str| -> String {
        let file = dir.path().join(name);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustock-cli"));
        cmd.args(["--network-id", "33", "--no-rpc", "--log-to-stdout"])
            .arg("--data-dir")
            .arg(dir.path().join("db"))
            .args(["--trie-backend", "external", "--trie-dir"])
            .arg(dir.path().join("trie"))
            .arg("--export-blocks")
            .arg(&file)
            .args(["--export-from", from]);
        if let Some(to) = to {
            cmd.args(["--export-to", to]);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if name.ends_with(".gz") {
            let mut text = String::new();
            flate2::read::MultiGzDecoder::new(std::fs::File::open(&file).unwrap())
                .read_to_string(&mut text)
                .unwrap();
            text
        } else {
            std::fs::read_to_string(&file).unwrap()
        }
    };

    // The whole chain, to the best block.
    let all = export("1", None, "all.txt");
    assert_eq!(all.lines().collect::<Vec<_>>(), expected);
    // A range, and gzip output.
    let some = export("5", Some("9"), "some.txt.gz");
    assert_eq!(some.lines().collect::<Vec<_>>(), &expected[4..9]);
}
