//! Timestamped, thread-safe file logging for every audited action.

use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;

/// Appends timestamped audit lines to a single log file.
///
/// Lines have the shape:
///
/// ```text
/// 2026-10-25T12:00:00.123Z [INFO] attempt start target=10.0.0.5:3389 user=alice password=a*****
/// ```
///
/// The logger is deliberately dependency-free (no `tracing` subscriber wiring) so
/// that the binary keeps full control over the on-disk audit trail.
pub struct AuditLogger {
    file: Mutex<File>,
    path: PathBuf,
}

impl AuditLogger {
    /// Creates (or opens for append) the log file at `path`.
    ///
    /// Parent directories are created when missing. Every subsequent
    /// [`AuditLogger::log`] call appends one line and flushes immediately, so a
    /// crash can never lose earlier audit records.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            file: Mutex::new(file),
            path,
        })
    }

    /// Writes one line: `<RFC3339 timestamp> [LEVEL] message`.
    pub fn log(&self, level: &str, message: &str) {
        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let line = format!("{timestamp} [{level}] {message}\n");
        // A poisoned lock must not take the whole audit down; skip the line instead.
        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }

    /// Logs an informational line.
    pub fn info(&self, message: &str) {
        self.log("INFO", message);
    }

    /// Logs a warning line (rate-limit slips, leftover bytes, stopped users, ...).
    pub fn warn(&self, message: &str) {
        self.log("WARN", message);
    }

    /// Logs an error line (lockouts, halts, refused targets, ...).
    pub fn error(&self, message: &str) {
        self.log("ERROR", message);
    }

    /// Path of the log file this logger writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogger").field("path", &self.path).finish()
    }
}
