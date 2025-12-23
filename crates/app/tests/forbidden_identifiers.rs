use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

const FORBIDDEN_IDENTIFIERS: &[&str] = &[
    "ExecutionRequestLike",
    "OutcomeLike",
    "KeyEpochAnnouncement",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir has parent")
        .parent()
        .expect("workspace root exists")
        .to_path_buf()
}

fn is_test_path(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "tests")
}

#[test]
fn forbid_local_protocol_standins_in_production_sources() {
    let root = workspace_root();
    let mut offenders: Vec<(PathBuf, String)> = Vec::new();

    for entry in WalkDir::new(&root)
        .into_iter()
        .filter_entry(|e| !matches!(e.file_name().to_str(), Some(".git") | Some("target")))
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if entry.file_type().is_dir() {
            continue;
        }

        if entry.path().extension().is_none_or(|ext| ext != "rs") {
            continue;
        }

        if is_test_path(entry.path()) {
            continue;
        }

        let Ok(contents) = fs::read_to_string(entry.path()) else {
            continue;
        };

        for ident in FORBIDDEN_IDENTIFIERS {
            if contents.contains(ident) {
                offenders.push((entry.path().to_path_buf(), ident.to_string()));
            }
        }
    }

    if !offenders.is_empty() {
        let mut message = String::from("found forbidden stand-in identifiers outside tests:\n");
        for (path, ident) in offenders {
            message.push_str(&format!("{} -> {}\n", path.display(), ident));
        }
        panic!("{}", message);
    }
}
