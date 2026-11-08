//! Shared helpers for the integration tests.
//!
//! Everything here is intentionally network-free: the engine is exercised
//! through a scripted [`MockBackend`] so the audit logic (budgets, lockout
//! aborts, per-user stops) is tested deterministically.

#![allow(dead_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rdp_audit::logger::AuditLogger;
use rdp_audit::rdp_tester::{
    AuditConfig, AuthOutcome, Credential, RdpAuthBackend, RdpTester,
};

/// Monotonic counter so every test gets its own log file.
static LOG_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Builds a unique log path under the system temp directory.
pub fn temp_log_path(label: &str) -> String {
    let n = LOG_COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir()
        .join(format!(
            "rdp-audit-tests-{label}-{}-{n}.log",
            std::process::id()
        ))
        .to_string_lossy()
        .into_owned()
}

/// Scripted backend: the handler closure decides each outcome from the
/// credential under test (username AND password are visible to it).
pub struct MockBackend {
    /// Decides the outcome of one authentication attempt.
    pub handler: Arc<dyn Fn(&Credential) -> AuthOutcome + Send + Sync>,
}

impl RdpAuthBackend for MockBackend {
    fn attempt<'a>(
        &'a self,
        credential: &'a Credential,
    ) -> Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>> {
        let handler = Arc::clone(&self.handler);
        Box::pin(async move { handler.as_ref()(credential) })
    }
}

/// Builds a test configuration with sensible lab defaults.
///
/// `delay` is zero here; the engine's validation raises it to its anti-thrash
/// floor (250 ms), which keeps the tests fast while still exercising the
/// pacing path.
pub fn test_config(
    usernames: &[&str],
    passwords: &[&str],
    concurrency: usize,
    max_attempts: usize,
    log_path: &str,
) -> AuditConfig {
    AuditConfig {
        target: "lab.example.com".to_string(),
        ip: "127.0.0.1".parse().expect("valid ip"),
        port: 3389,
        usernames: usernames.iter().map(|u| u.to_string()).collect(),
        passwords: passwords.iter().map(|p| p.to_string()).collect(),
        domain: None,
        delay: Duration::ZERO,
        max_attempts,
        concurrency,
        timeout: Duration::from_secs(5),
        log_path: log_path.to_string(),
    }
}

/// Builds an [`RdpTester`] wired to a scripted mock handler.
pub fn make_tester<F>(
    config: AuditConfig,
    log_path: &str,
    handler: F,
) -> RdpTester
where
    F: Fn(&Credential) -> AuthOutcome + Send + Sync + 'static,
{
    let logger = Arc::new(AuditLogger::create(log_path).expect("temp log file"));
    let backend = Arc::new(MockBackend {
        handler: Arc::new(handler),
    });
    RdpTester::with_backend(config, logger, backend)
}
