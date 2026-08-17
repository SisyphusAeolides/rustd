// SPDX-License-Identifier: LGPL-2.1-or-later
//! Event-driven `.path` unit activation.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context};

use crate::event::loop_::{EventLoop, InotifyHandler};
use crate::event::source::SourceId;
use crate::job::{JobKind, JobQueue};
use crate::service::UnitRecord;
use crate::unit::loader::LoadedUnit;
use crate::unit::section_path::PathSpec;
use crate::unit::UnitState;

const WATCH_MASK: u32 = libc::IN_ATTRIB
    | libc::IN_CLOSE_WRITE
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_DELETE_SELF
    | libc::IN_MODIFY
    | libc::IN_MOVE_SELF
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO;

/// Register path watches and trigger the companion unit when a condition is met.
///
/// # Errors
/// Returns an error for invalid path-unit configuration or failed inotify
/// registration.
pub fn activate_path(
    record: &mut UnitRecord,
    event_loop: &mut EventLoop,
    queue: &Arc<Mutex<JobQueue>>,
) -> anyhow::Result<SourceId> {
    let LoadedUnit::Path(path_unit) = &record.loaded else {
        return Err(anyhow!("activate_path called for non-path unit"));
    };
    if path_unit.specific.watches.is_empty() {
        return Err(anyhow!("path unit has no Path*= watches"));
    }
    let target = if path_unit.specific.unit.is_empty() {
        record.loaded.name().strip_suffix(".path").map_or_else(
            || format!("{}.service", record.loaded.name()),
            |stem| format!("{stem}.service"),
        )
    } else {
        path_unit.specific.unit.clone()
    };

    if path_unit.specific.make_directory {
        for watch in &path_unit.specific.watches {
            if let Some(parent) = Path::new(&watch.path).parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create path-unit directory {}", parent.display()))?;
            }
        }
    }

    let source_id = event_loop.add_inotify(Box::new(PathChangedHandler {
        unit_name: target.clone(),
        queue: Arc::clone(queue),
    }))?;
    for watch in &path_unit.specific.watches {
        let watched_path = watch_root(&watch.path);
        if let Err(error) =
            event_loop.inotify_add_watch(source_id, &watched_path.to_string_lossy(), WATCH_MASK)
        {
            let _ = event_loop.remove_inotify(source_id);
            return Err(error);
        }
    }

    if path_unit.specific.watches.iter().any(path_condition_met) {
        if let Ok(mut queue) = queue.lock() {
            queue.enqueue(JobKind::Start, target);
        }
    }
    record.state = UnitState::Active;
    Ok(source_id)
}

fn watch_root(configured: &str) -> PathBuf {
    let configured = Path::new(configured);
    let mut candidate = if contains_glob(configured) {
        configured.parent().unwrap_or(Path::new("/"))
    } else if configured.exists() {
        configured
    } else {
        configured.parent().unwrap_or(Path::new("/"))
    };
    while !candidate.exists() {
        candidate = candidate.parent().unwrap_or(Path::new("/"));
    }
    candidate.to_path_buf()
}

fn path_condition_met(spec: &PathSpec) -> bool {
    match spec.kind.as_str() {
        "PathExists" => Path::new(&spec.path).exists(),
        "PathExistsGlob" => glob_exists(&spec.path),
        "DirectoryNotEmpty" => fs::read_dir(&spec.path)
            .ok()
            .and_then(|mut entries| entries.next())
            .is_some(),
        // Changed/Modified are edge-triggered and must not fire merely because
        // the path existed when the unit was activated.
        "PathChanged" | "PathModified" => false,
        _ => false,
    }
}

fn glob_exists(pattern: &str) -> bool {
    let path = Path::new(pattern);
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(file_pattern) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    fs::read_dir(parent).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| crate::glob::matches_no_escape(file_pattern, name))
        })
    })
}

fn contains_glob(path: &Path) -> bool {
    path.as_os_str()
        .as_encoded_bytes()
        .iter()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

struct PathChangedHandler {
    unit_name: String,
    queue: Arc<Mutex<JobQueue>>,
}

impl InotifyHandler for PathChangedHandler {
    fn on_inotify(&mut self, _wd: i32, mask: u32, _path: Option<&str>) {
        if mask & WATCH_MASK == 0 {
            return;
        }
        if let Ok(mut queue) = self.queue.lock() {
            queue.enqueue(JobKind::Start, self.unit_name.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::loader::{LoadedUnit, ParsedUnit};
    use crate::unit::section_install::InstallSection;
    use crate::unit::section_path::PathSection;
    use crate::unit::section_unit::UnitSection;

    #[test]
    fn existing_path_triggers_companion_immediately() {
        let root = tempfile::tempdir().unwrap();
        let watched = root.path().join("ready");
        fs::write(&watched, "ready").unwrap();
        let loaded = LoadedUnit::Path(Box::new(ParsedUnit {
            name: "ready.path".to_owned(),
            source_path: PathBuf::from("/fake/ready.path"),
            unit: UnitSection::default(),
            install: InstallSection::default(),
            specific: PathSection {
                watches: vec![PathSpec {
                    kind: "PathExists".to_owned(),
                    path: watched.display().to_string(),
                }],
                ..Default::default()
            },
        }));
        let mut record = UnitRecord::new(loaded);
        let mut event_loop = EventLoop::new().unwrap();
        let queue = Arc::new(Mutex::new(JobQueue::default()));
        let source = activate_path(&mut record, &mut event_loop, &queue).unwrap();

        let job = queue.lock().unwrap().pop_front().unwrap();
        assert_eq!(job.unit_name, "ready.service");
        event_loop.remove_inotify(source).unwrap();
    }

    #[test]
    fn absent_path_is_watched_via_existing_parent() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("one/two/ready");
        assert_eq!(watch_root(&missing.to_string_lossy()), root.path());
    }
}
