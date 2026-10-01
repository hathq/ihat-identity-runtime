use std::{fs, path::Path};

#[test]
fn every_production_rust_source_has_at_most_149_noncomment_lines() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect(&root, &mut files);
    for path in files {
        let source = fs::read_to_string(&path).unwrap();
        let lines = source
            .lines()
            .filter(|line| {
                let line = line.trim();
                !line.is_empty() && !line.starts_with("//")
            })
            .count();
        assert!(
            lines <= 149,
            "{} has {lines} noncomment lines",
            path.display()
        );
    }
}

fn collect(directory: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}
