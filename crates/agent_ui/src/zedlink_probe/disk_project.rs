//! Serves `project.*` for local projects that no Zed window has open, straight from disk
//! with the same visibility rules a worktree applies.

use ignore::WalkBuilder;
use worktree::WorktreeSettings;

use super::*;

pub(super) struct DiskEntry {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Clone)]
pub(super) enum DiskScope {
    Tree,
    /// Direct children of a directory; the empty path is the root.
    Directory(String),
    File(String),
}

impl DiskScope {
    fn descends(&self, path: &str) -> bool {
        let leads_to = |target: &str| {
            target == path
                || target
                    .strip_prefix(path)
                    .is_some_and(|rest| rest.starts_with('/'))
        };
        match self {
            DiskScope::Tree => true,
            DiskScope::Directory(directory) => leads_to(directory) || is_child(directory, path),
            DiskScope::File(file) => leads_to(file),
        }
    }

    fn yields(&self, path: &str, is_dir: bool) -> bool {
        match self {
            DiskScope::Tree => true,
            DiskScope::Directory(directory) => is_child(directory, path),
            DiskScope::File(file) => !is_dir && file == path,
        }
    }
}

fn is_child(directory: &str, path: &str) -> bool {
    let rest = if directory.is_empty() {
        Some(path)
    } else {
        path.strip_prefix(directory)
            .and_then(|rest| rest.strip_prefix('/'))
    };
    rest.is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
}

fn unix_relative(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let parts = relative
        .components()
        .map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    Some(parts.join("/"))
}

fn is_listable(path: &str, settings: &WorktreeSettings) -> bool {
    !excluded_remote_path(path)
        && RelPath::from_unix_str(path).is_ok_and(|path| {
            !settings.is_path_private(path)
                && !settings.is_path_excluded(path)
                && !settings.is_path_hidden(path)
        })
}

/// Walks `root` (canonical) honouring .gitignore and Zed's hidden, private and excluded files.
/// Symlinks are not followed or listed, so every yielded path stays under `root`. Returns at
/// most `limit` entries and whether more were found.
pub(super) fn disk_entries(
    root: &Path,
    scope: DiskScope,
    files_only: bool,
    limit: usize,
    settings: &WorktreeSettings,
) -> (Vec<DiskEntry>, bool) {
    let walk = WalkBuilder::new(root)
        .hidden(true)
        .follow_links(false)
        .require_git(false)
        .sort_by_file_name(|left, right| left.cmp(right))
        .filter_entry({
            let root = root.to_path_buf();
            let scope = scope.clone();
            let settings = settings.clone();
            move |entry| {
                entry.depth() == 0
                    || unix_relative(&root, entry.path())
                        .is_some_and(|path| is_listable(&path, &settings) && scope.descends(&path))
            }
        })
        .build();
    let mut entries = Vec::new();
    for entry in walk {
        let Ok(entry) = entry else {
            continue;
        };
        if entry.depth() == 0 {
            continue;
        }
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        let is_dir = file_type.is_dir();
        if !is_dir && !file_type.is_file() {
            continue;
        }
        if files_only && is_dir {
            continue;
        }
        let Some(path) = unix_relative(root, entry.path()) else {
            continue;
        };
        if !scope.yields(&path, is_dir) {
            continue;
        }
        if entries.len() == limit {
            return (entries, true);
        }
        let size = if is_dir {
            0
        } else {
            entry.metadata().map_or(0, |metadata| metadata.len())
        };
        entries.push(DiskEntry { path, is_dir, size });
    }
    (entries, false)
}

/// `path` must already be a validated relative path.
pub(super) fn disk_directory_allowed(root: &Path, path: &str, settings: &WorktreeSettings) -> bool {
    if path.is_empty() {
        return true;
    }
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    let (entries, _) = disk_entries(
        root,
        DiskScope::Directory(parent.to_string()),
        false,
        usize::MAX,
        settings,
    );
    entries
        .iter()
        .any(|entry| entry.is_dir && entry.path == path)
        && fs::canonicalize(root.join(path))
            .is_ok_and(|absolute| absolute.starts_with(root) && absolute.is_dir())
}

/// `path` must already be a validated relative path.
pub(super) fn disk_file(
    root: &Path,
    path: &str,
    settings: &WorktreeSettings,
) -> std::result::Result<PathBuf, &'static str> {
    let (entries, _) = disk_entries(root, DiskScope::File(path.to_string()), true, 1, settings);
    if entries.is_empty() {
        return Err("FILE_UNAVAILABLE");
    }
    let candidate = fs::canonicalize(root.join(path)).map_err(|_| "FILE_UNAVAILABLE")?;
    if !candidate.starts_with(root) || !candidate.is_file() {
        return Err("FILE_UNAVAILABLE");
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use util::paths::{PathMatcher, PathStyle};

    fn settings() -> WorktreeSettings {
        let matcher = |patterns: &[&str]| {
            PathMatcher::new(patterns.iter().copied(), PathStyle::local()).unwrap_or_default()
        };
        WorktreeSettings {
            prevent_sharing_in_public_channels: false,
            file_scan_exclusions: matcher(&["**/.git"]),
            file_scan_inclusions: matcher(&[]),
            parent_dir_scan_inclusions: matcher(&[]),
            scan_symlinks: Default::default(),
            file_scan_depth: None,
            private_files: matcher(&["**/*.crt"]),
            hidden_files: matcher(&[]),
            read_only_files: matcher(&[]),
        }
    }

    fn project() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = fs::canonicalize(directory.path()).expect("canonical root");
        for (path, content) in [
            (".gitignore", "build/\n*.log\n"),
            ("README.md", "hello world"),
            ("src/main.rs", "fn main() { hello(); }"),
            ("src/nested/lib.rs", "pub fn hello() {}"),
            ("build/out.txt", "hello"),
            ("debug.log", "hello"),
            ("server.crt", "hello"),
            ("secret.pem", "hello"),
            (".env", "TOKEN=hello"),
            ("node_modules/package/index.js", "hello"),
        ] {
            let absolute = root.join(path);
            if let Some(parent) = absolute.parent() {
                fs::create_dir_all(parent).expect("create directory");
            }
            fs::write(absolute, content).expect("write file");
        }
        (directory, root)
    }

    fn paths(entries: &[DiskEntry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.path.as_str()).collect()
    }

    #[test]
    fn tree_listing_skips_ignored_hidden_private_and_excluded() {
        let (_directory, root) = project();
        let (entries, truncated) = disk_entries(&root, DiskScope::Tree, false, 100, &settings());
        assert!(!truncated);
        assert_eq!(
            paths(&entries),
            [
                "README.md",
                "src",
                "src/main.rs",
                "src/nested",
                "src/nested/lib.rs"
            ]
        );
        assert_eq!(entries[0].size, 11);
        assert!(entries[1].is_dir);

        let (files, truncated) = disk_entries(&root, DiskScope::Tree, true, 2, &settings());
        assert!(truncated);
        assert_eq!(paths(&files), ["README.md", "src/main.rs"]);
    }

    #[test]
    fn directory_listing_returns_direct_children() {
        let (_directory, root) = project();
        let (entries, _) = disk_entries(
            &root,
            DiskScope::Directory(String::new()),
            false,
            100,
            &settings(),
        );
        assert_eq!(paths(&entries), ["README.md", "src"]);
        let (entries, _) = disk_entries(
            &root,
            DiskScope::Directory("src".to_string()),
            false,
            100,
            &settings(),
        );
        assert_eq!(paths(&entries), ["src/main.rs", "src/nested"]);
        assert!(disk_directory_allowed(&root, "src/nested", &settings()));
        assert!(!disk_directory_allowed(&root, "build", &settings()));
        assert!(!disk_directory_allowed(&root, "missing", &settings()));
    }

    #[test]
    fn file_access_follows_listing_rules() {
        let (_directory, root) = project();
        assert_eq!(
            disk_file(&root, "src/nested/lib.rs", &settings()),
            Ok(root.join("src/nested/lib.rs"))
        );
        for path in [
            "build/out.txt",
            "debug.log",
            "server.crt",
            "secret.pem",
            "src",
            "missing.rs",
        ] {
            assert_eq!(
                disk_file(&root, path, &settings()),
                Err("FILE_UNAVAILABLE"),
                "{path}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_out_of_the_root_are_not_served() {
        let (_directory, root) = project();
        let outside = tempfile::tempdir().expect("temporary directory");
        fs::write(outside.path().join("secret.txt"), "outside").expect("write file");
        std::os::unix::fs::symlink(outside.path(), root.join("linked")).expect("symlink");
        std::os::unix::fs::symlink(outside.path().join("secret.txt"), root.join("file.txt"))
            .expect("symlink");
        let (entries, _) = disk_entries(&root, DiskScope::Tree, false, 100, &settings());
        assert!(
            !paths(&entries)
                .iter()
                .any(|path| path.starts_with("linked") || *path == "file.txt")
        );
        assert_eq!(
            disk_file(&root, "file.txt", &settings()),
            Err("FILE_UNAVAILABLE")
        );
        assert_eq!(
            disk_file(&root, "linked/secret.txt", &settings()),
            Err("FILE_UNAVAILABLE")
        );
    }
}
