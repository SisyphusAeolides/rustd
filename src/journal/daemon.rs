// SPDX-License-Identifier: LGPL-2.1-or-later
//! `RustD` journal daemon runtime wiring.
//!
//! The daemon keeps the externally visible journal sockets in a configurable
//! directory. Installed execution uses the native `/run/rustd/journal` path,
//! while tests and service sandboxes can select a private directory.
//! Pre-existing socket paths are never removed by this implementation. Socket
//! paths created by a daemon instance are removed when that instance exits.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::event::{EventLoop, LoopResult};
use crate::journal::entry::EntryRing;
use crate::journal::receiver::JournalReceiver;
use crate::journal::sink::JournalSink;
use crate::journal::stdout::StdoutServer;
use crate::journal::writer::JournalWriter;

/// Default runtime directory for an installed `RustD` journal daemon.
pub const DEFAULT_RUNTIME_DIRECTORY: &str = "/run/rustd/journal";
/// Default directory for an installed persistent journal daemon.
pub const DEFAULT_JOURNAL_DIRECTORY: &str = "/var/log/journal";
/// Default persistent journal filename.
pub const DEFAULT_JOURNAL_FILENAME: &str = "system.journal";

/// Configuration for one journal daemon instance.
#[derive(Debug, Clone)]
pub struct JournalDaemonConfig {
    /// Directory containing the `socket` and `stdout` UNIX socket paths.
    pub runtime_directory: PathBuf,
    /// Directory used for the default persistent journal filename.
    pub journal_directory: PathBuf,
    /// Optional explicit journal file path.
    pub journal_file: Option<PathBuf>,
    /// Maximum number of entries retained for in-process consumers.
    pub ring_capacity: usize,
}

impl Default for JournalDaemonConfig {
    fn default() -> Self {
        Self {
            runtime_directory: PathBuf::from(DEFAULT_RUNTIME_DIRECTORY),
            journal_directory: PathBuf::from(DEFAULT_JOURNAL_DIRECTORY),
            journal_file: None,
            ring_capacity: 8192,
        }
    }
}

impl JournalDaemonConfig {
    /// Return the file receiving persistent entries.
    #[must_use]
    pub fn journal_path(&self) -> PathBuf {
        self.journal_file
            .clone()
            .unwrap_or_else(|| self.journal_directory.join(DEFAULT_JOURNAL_FILENAME))
    }
}

/// A running journal daemon with registered datagram and stdout listeners.
pub struct JournalDaemon {
    event_loop: EventLoop,
    sink: Arc<JournalSink>,
    _compatibility_links: Vec<SymlinkGuard>,
}

impl JournalDaemon {
    /// Create the daemon and bind its two journal sockets.
    ///
    /// `runtime_directory` and the journal file parent are created when they
    /// do not exist. A pre-existing `socket` or `stdout` path is an error,
    /// preventing an accidental replacement of a live host journal socket.
    /// Paths successfully created by this instance are removed during teardown.
    ///
    /// # Errors
    /// Returns an error if storage cannot be initialized, an existing socket
    /// blocks startup, or event source registration fails.
    pub fn new(config: &JournalDaemonConfig) -> anyhow::Result<Self> {
        prepare_directory(&config.runtime_directory)?;
        prepare_directory(&config.journal_directory)?;

        let journal_path = config.journal_path();
        let journal_parent = journal_path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "journal file {} has no parent directory",
                journal_path.display()
            )
        })?;
        prepare_directory(journal_parent)?;

        let ring = Arc::new(Mutex::new(EntryRing::new(config.ring_capacity)));
        let writer = JournalWriter::open_resilient(&journal_path)?;
        let sink = JournalSink::with_writer(ring, writer);

        let receiver_path = config.runtime_directory.join("socket");
        let stdout_path = config.runtime_directory.join("stdout");

        // Create the signal source before exposing either socket. A SIGTERM
        // arriving during startup is then delivered through signalfd rather
        // than terminating the daemon between the two binds.
        let mut event_loop = EventLoop::new()?;

        let receiver = JournalReceiver::bind_at(&receiver_path, Arc::clone(&sink))?;
        let stdout = StdoutServer::bind_at(&stdout_path, Arc::clone(&sink))?;

        event_loop.add_io(receiver.raw_fd(), libc::EPOLLIN as u32, Box::new(receiver))?;
        event_loop.add_io(stdout.raw_fd(), libc::EPOLLIN as u32, Box::new(stdout))?;

        let compatibility_links =
            if config.runtime_directory == Path::new(DEFAULT_RUNTIME_DIRECTORY) {
                install_compatibility_links(
                    &config.runtime_directory,
                    Path::new("/run/systemd/journal"),
                )?
            } else {
                Vec::new()
            };

        Ok(Self {
            event_loop,
            sink,
            _compatibility_links: compatibility_links,
        })
    }

    /// Dispatch journal socket events until a terminating signal is received.
    ///
    /// SIGTERM is handled by the shared event loop and maps to
    /// [`LoopResult::Exit`]. On every exit path the journal writer is flushed
    /// and closed before this method returns.
    ///
    /// # Errors
    /// Returns an error from the event loop, journal persistence, or final
    /// writer close.
    pub fn run(mut self) -> anyhow::Result<LoopResult> {
        let outcome = loop {
            match self.event_loop.run_once() {
                Ok(result) => {
                    if let Some(failure) = self.sink.failure() {
                        break Err(anyhow::anyhow!("journal persistence failed: {failure}"));
                    }
                    if result != LoopResult::Continue {
                        break Ok(result);
                    }
                }
                Err(error) => break Err(error),
            }
        };

        drop(self.event_loop);
        match (outcome, self.sink.shutdown()) {
            (Ok(result), Ok(())) => Ok(result),
            (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
            (Err(error), Err(shutdown_error)) => Err(anyhow::anyhow!(
                "journal event loop failed: {error}; journal shutdown also failed: {shutdown_error}"
            )),
        }
    }
}

struct SymlinkGuard {
    path: PathBuf,
    target: PathBuf,
    owned: bool,
}

impl Drop for SymlinkGuard {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        if std::fs::read_link(&self.path).ok().as_deref() == Some(self.target.as_path()) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn install_compatibility_links(
    runtime_directory: &Path,
    compatibility_directory: &Path,
) -> anyhow::Result<Vec<SymlinkGuard>> {
    prepare_directory(compatibility_directory)?;
    let mut guards = Vec::new();
    for name in ["socket", "stdout"] {
        let target = runtime_directory.join(name);
        let path = compatibility_directory.join(name);
        match std::fs::read_link(&path) {
            Ok(existing) if existing == target => guards.push(SymlinkGuard {
                path,
                target,
                owned: false,
            }),
            Ok(existing) => {
                anyhow::bail!(
                    "journal compatibility link {} points to {} instead of {}",
                    path.display(),
                    existing.display(),
                    target.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                anyhow::bail!(
                    "journal compatibility path {} exists and is not a symlink",
                    path.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                symlink(&target, &path).map_err(|error| {
                    anyhow::anyhow!(
                        "create journal compatibility link {} -> {}: {error}",
                        path.display(),
                        target.display()
                    )
                })?;
                guards.push(SymlinkGuard {
                    path,
                    target,
                    owned: true,
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(guards)
}

fn prepare_directory(path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "journal directory must be absolute: {}",
            path.display()
        ));
    }
    std::fs::create_dir_all(path)
        .map_err(|error| anyhow::anyhow!("create journal directory {}: {error}", path.display()))?;
    if !std::fs::metadata(path)?.is_dir() {
        return Err(anyhow::anyhow!(
            "journal path is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_match_rustd_locations() {
        let config = JournalDaemonConfig::default();
        assert_eq!(
            config.runtime_directory,
            Path::new(DEFAULT_RUNTIME_DIRECTORY)
        );
        assert_eq!(config.runtime_directory, Path::new("/run/rustd/journal"));
        assert_eq!(
            config.journal_path(),
            Path::new("/var/log/journal/system.journal")
        );
    }

    #[test]
    fn journal_path_can_be_overridden() {
        let config = JournalDaemonConfig {
            journal_file: Some(PathBuf::from("/tmp/private.journal")),
            ..JournalDaemonConfig::default()
        };
        assert_eq!(config.journal_path(), Path::new("/tmp/private.journal"));
    }

    #[test]
    fn rejects_relative_runtime_directory() {
        let error = prepare_directory(Path::new("relative/runtime")).unwrap_err();
        assert!(error.to_string().contains("must be absolute"));
    }

    #[test]
    fn compatibility_links_target_native_sockets_and_clean_up_owned_paths() {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("run/rustd/journal");
        let compatibility = root.path().join("run/systemd/journal");
        prepare_directory(&runtime).unwrap();

        let guards = install_compatibility_links(&runtime, &compatibility).unwrap();
        assert_eq!(
            std::fs::read_link(compatibility.join("socket")).unwrap(),
            runtime.join("socket")
        );
        assert_eq!(
            std::fs::read_link(compatibility.join("stdout")).unwrap(),
            runtime.join("stdout")
        );
        drop(guards);
        assert!(std::fs::symlink_metadata(compatibility.join("socket")).is_err());
        assert!(std::fs::symlink_metadata(compatibility.join("stdout")).is_err());
    }

    #[test]
    fn compatibility_links_refuse_to_replace_existing_paths() {
        let root = tempfile::tempdir().unwrap();
        let runtime = root.path().join("run/rustd/journal");
        let compatibility = root.path().join("run/systemd/journal");
        prepare_directory(&runtime).unwrap();
        prepare_directory(&compatibility).unwrap();
        std::fs::write(compatibility.join("socket"), "owned elsewhere").unwrap();
        assert!(install_compatibility_links(&runtime, &compatibility).is_err());
    }
}
