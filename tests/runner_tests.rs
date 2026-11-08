//! Integration tests for the audit engine's decision logic.
//!
//! All tests use the scripted [`MockBackend`] from `tests/common`: no socket is
//! ever opened and no real RDP server is contacted.

mod common;

use common::{make_tester, temp_log_path, test_config};
use rdp_audit::{AuthOutcome, HaltReason};

/// A valid credential stops further attempts for that username only.
#[tokio::test]
async fn stops_after_valid_credential() {
    let log = temp_log_path("valid");
    let config = test_config(&["alice"], &["wrong1", "correct", "never"], 1, 10, &log);
    let tester = make_tester(config, &log, |credential| {
        if credential.password == "correct" {
            AuthOutcome::ValidCredentials
        } else {
            AuthOutcome::LogonFailure
        }
    });

    let summary = tester.run().await;

    assert!(summary.found_valid());
    assert_eq!(summary.valid_credentials.len(), 1);
    assert_eq!(summary.valid_credentials[0].username, "alice");
    assert_eq!(summary.valid_credentials[0].password, "correct");
    // wrong1, then correct; "never" is never attempted.
    assert_eq!(summary.attempts_used, 2);
    assert!(summary.halted.is_none());
}

/// A lockout aborts the whole run immediately: with one worker exactly two
/// attempts happen (the failing one and the lockout).
#[tokio::test]
async fn halts_immediately_on_lockout() {
    let log = temp_log_path("lockout");
    let config = test_config(&["bob"], &["pw1", "pw2", "pw3"], 1, 10, &log);
    let tester = make_tester(config, &log, |credential| {
        if credential.password == "pw2" {
            AuthOutcome::AccountLockedOut
        } else {
            AuthOutcome::LogonFailure
        }
    });

    let summary = tester.run().await;

    assert_eq!(summary.attempts_used, 2, "must stop at the first lockout");
    assert_eq!(
        summary.halted,
        Some(HaltReason::AccountLockout {
            username: "bob".to_string()
        })
    );
    // Both attempts are reported, including the lockout itself.
    assert_eq!(summary.reports.len(), 2);
    assert!(summary.reports.iter().any(|r| r.outcome == AuthOutcome::AccountLockedOut));
}

/// The global attempt budget is a hard cap regardless of wordlist size.
#[tokio::test]
async fn respects_max_attempts() {
    let log = temp_log_path("budget");
    let passwords: Vec<String> = (0..10).map(|i| format!("pw{i}")).collect();
    let password_refs: Vec<&str> = passwords.iter().map(String::as_str).collect();
    let config = test_config(&["carol"], &password_refs, 1, 3, &log);
    let tester = make_tester(config, &log, |_credential| AuthOutcome::LogonFailure);

    let summary = tester.run().await;

    assert_eq!(summary.attempts_used, 3);
    assert_eq!(summary.reports.len(), 3);
    assert!(summary.halted.is_none());
}

/// Five consecutive connection errors abort the run as "target unreachable".
#[tokio::test]
async fn aborts_when_target_unreachable() {
    let log = temp_log_path("unreachable");
    let passwords: Vec<String> = (0..8).map(|i| format!("pw{i}")).collect();
    let password_refs: Vec<&str> = passwords.iter().map(String::as_str).collect();
    let config = test_config(&["dave"], &password_refs, 1, 20, &log);
    let tester = make_tester(config, &log, |_credential| AuthOutcome::ConnectionError);

    let summary = tester.run().await;

    assert_eq!(summary.halted, Some(HaltReason::TargetUnreachable));
    assert_eq!(summary.attempts_used, 5);
    assert_eq!(summary.reports.len(), 5);
}

/// Access-denied means the password is right but the account may not use RDP:
/// the username stops, but the rest of the audit continues.
#[tokio::test]
async fn stops_user_on_access_denied() {
    let log = temp_log_path("denied");
    let config = test_config(&["alice", "bob"], &["correct"], 1, 10, &log);
    let tester = make_tester(config, &log, |credential| {
        if credential.username == "alice" {
            AuthOutcome::AccessDenied
        } else {
            AuthOutcome::LogonFailure
        }
    });

    let summary = tester.run().await;

    assert_eq!(summary.access_denied, vec!["alice".to_string()]);
    assert!(!summary.found_valid());
    assert_eq!(summary.attempts_used, 2);
    assert!(summary.halted.is_none());
}

/// A valid credential for one user does not prevent testing the next user.
#[tokio::test]
async fn valid_credential_stops_that_user_only() {
    let log = temp_log_path("multi-user");
    let config = test_config(&["alice", "bob"], &["correct", "bogus"], 1, 10, &log);
    let tester = make_tester(config, &log, |credential| {
        if credential.password == "correct" {
            AuthOutcome::ValidCredentials
        } else {
            AuthOutcome::LogonFailure
        }
    });

    let summary = tester.run().await;

    assert_eq!(summary.valid_credentials.len(), 2);
    // alice:correct, bob:correct — the bogus password is never reached.
    assert_eq!(summary.attempts_used, 2);
}

/// Restricted accounts (disabled / logon hours / workstation policy) stop the
/// username without being reported as valid credentials.
#[tokio::test]
async fn stops_user_on_account_restriction() {
    let log = temp_log_path("restricted");
    let config = test_config(&["eve"], &["pw1", "pw2"], 1, 10, &log);
    let tester = make_tester(config, &log, |_credential| AuthOutcome::AccountRestricted);

    let summary = tester.run().await;

    assert_eq!(summary.restricted, vec!["eve".to_string()]);
    assert_eq!(summary.attempts_used, 1);
    assert!(!summary.found_valid());
}

/// Failed passwords are masked in the log; only confirmed valid credentials
/// are written in clear text.
#[tokio::test]
async fn log_masks_failed_passwords_but_records_valid_ones() {
    let log = temp_log_path("masking");
    let config = test_config(&["alice"], &["wrong1", "correct"], 1, 10, &log);
    let tester = make_tester(config, &log, |credential| {
        if credential.password == "correct" {
            AuthOutcome::ValidCredentials
        } else {
            AuthOutcome::LogonFailure
        }
    });

    let summary = tester.run().await;
    assert_eq!(summary.valid_credentials.len(), 1);

    let contents = std::fs::read_to_string(&log).expect("log file readable");
    assert!(
        !contents.contains("wrong1"),
        "failed passwords must never be logged in clear text"
    );
    assert!(
        contents.contains("<6 chars>"),
        "masked placeholder for the failed password is expected"
    );
    assert!(
        contents.contains("VALID_CREDENTIALS") && contents.contains("password=correct"),
        "confirmed credentials are recorded in clear text"
    );
    assert!(contents.contains("ACCOUNT") || contents.contains("LOGON_FAILURE"));
}
