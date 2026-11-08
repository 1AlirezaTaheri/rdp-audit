//! Command-line entry point for `rdp-audit`.
//!
//! Responsibilities:
//!
//! * print the mandatory authorization banner,
//! * enforce the `--i-have-authorization` gate and the private-target gate,
//! * assemble and validate the [`AuditConfig`] (one run per target),
//! * run the audit and print a final report with a meaningful exit code.
//!
//! Interface (single-dash spellings as requested):
//!
//! ```text
//! -p <IP>       one target IP / hostname        (also --ip)
//! -list <FILE>  file with target IPs            (also --ip-list)
//! -u <USER>     one username                    (also --username)
//! -ul <FILE>    file with usernames             (also --user-list)
//! -pl <FILE>    file with passwords             (also --password-list)
//! ```

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;

use rdp_audit::{AuditConfig, AuditSummary, HaltReason, RdpTester, ensure_target_allowed};

/// Exit code: the run completed and no valid credential was found.
const EXIT_COMPLETED_NO_FINDING: u8 = 0;
/// Exit code: the tool refused to run (authorization, safety, or config).
const EXIT_REFUSED: u8 = 1;
/// Exit code: at least one valid credential was found.
const EXIT_VALID_FOUND: u8 = 3;
/// Exit code: the run was aborted (account lockout or unreachable target).
const EXIT_ABORTED: u8 = 4;

/// The mandatory safety banner. The second line is intentionally kept
/// verbatim; it is part of the tool's contract with its operator.
const BANNER: &str = "\
================================ rdp-audit ================================
 FOR AUTHORIZED TESTING ONLY. Unauthorized access is illegal.
 Use only against systems you own or have explicit written permission to test.
 This tool performs rate-limited RDP authentication attempts (NLA/CredSSP or TLS).
==========================================================================";

/// RDP/NLA credential audit tool for authorized penetration-test labs.
#[derive(Parser, Debug)]
#[command(
    name = "rdp-audit",
    version,
    about = "Educational RDP/NLA (CredSSP) credential audit tool for authorized labs",
    long_about = "Tests RDP credentials using a native Rust implementation (IronRDP) — no \
external binaries. The strongest security protocol offered by the target is negotiated \
automatically: NLA/CredSSP (precise verdicts, no session started) or TLS without NLA \
(a brief session is started and dropped right after the verdict). Safety rails are \
mandatory: an explicit authorization flag, private-network refusal, bounded attempts, \
per-worker delays, and an immediate stop on account lockout.",
    after_help = "EXAMPLES:
  rdp-audit -p 192.168.174.133 -u testuser -pl passwords.txt --i-have-authorization --allow-private
  rdp-audit -list targets.txt -ul users.txt -pl passwords.txt --i-have-authorization --allow-private

NOTE:
  -list, -ul and -pl are accepted as the single-dash spellings of
  --ip-list, --user-list and --password-list."
)]
struct Cli {
    /// One target IP address or hostname.
    #[arg(short = 'p', long = "ip", visible_alias = "target", value_name = "IP")]
    ip: Option<String>,

    /// File with target IPs / hostnames, one per line ('#' comments allowed).
    #[arg(long = "ip-list", value_name = "FILE")]
    ip_list: Option<PathBuf>,

    /// One username to test.
    #[arg(short = 'u', long = "username", visible_alias = "user", value_name = "USER")]
    username: Option<String>,

    /// File with usernames, one per line ('#' comments allowed).
    #[arg(long = "user-list", visible_alias = "user-file", value_name = "FILE")]
    user_list: Option<PathBuf>,

    /// File with passwords, one per line ('#' comments allowed).
    #[arg(long = "password-list", visible_alias = "wordlist", value_name = "FILE")]
    password_list: PathBuf,

    /// RDP TCP port.
    #[arg(long, default_value_t = 3389, value_parser = clap::value_parser!(u16).range(1..=65535))]
    port: u16,

    /// Delay between attempts per worker, in milliseconds (default: 1000ms).
    #[arg(long, default_value_t = 1000)]
    delay: u64,

    /// Maximum number of credential attempts per target.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u64).range(1..))]
    max_attempts: u64,

    /// Number of concurrent workers (hard maximum: 8).
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=8))]
    concurrency: u64,

    /// Per-attempt timeout for the RDP/CredSSP handshake, in seconds.
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(5..=120))]
    timeout: u64,

    /// RDP domain / workgroup (optional).
    #[arg(long)]
    domain: Option<String>,

    /// Audit log file (timestamped, one line per action).
    #[arg(long, default_value = "rdp-audit.log")]
    log_file: PathBuf,

    /// Mandatory safety acknowledgment: you are authorized to test these targets.
    #[arg(long)]
    i_have_authorization: bool,

    /// Allow private/local targets (RFC1918, loopback, link-local, ...).
    #[arg(long)]
    allow_private: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse_from(normalized_args());
    println!("{BANNER}");

    match run_audit(&cli).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("\n[!] {error}");
            ExitCode::from(EXIT_REFUSED)
        }
    }
}

/// Rewrites the requested single-dash spellings into clap-style long options.
///
/// `-list`, `-ul` and `-pl` are not valid clap tokens on their own, so they are
/// translated before parsing; `-p` and `-u` are native short options already.
fn normalized_args() -> Vec<String> {
    std::env::args()
        .map(|arg| {
            if let Some(rest) = arg.strip_prefix("-list=") {
                format!("--ip-list={rest}")
            } else if let Some(rest) = arg.strip_prefix("-ul=") {
                format!("--user-list={rest}")
            } else if let Some(rest) = arg.strip_prefix("-pl=") {
                format!("--password-list={rest}")
            } else {
                match arg.as_str() {
                    "-list" => "--ip-list".to_string(),
                    "-ul" => "--user-list".to_string(),
                    "-pl" => "--password-list".to_string(),
                    _ => arg,
                }
            }
        })
        .collect()
}

/// Orchestrates the audit: gates, inputs, one run per target, exit code.
///
/// Any refusal (authorization, safety gate, configuration problem) is surfaced
/// as `Err(..)` and maps to exit code 1 before a single packet is sent.
async fn run_audit(cli: &Cli) -> Result<u8, String> {
    // --- Safety gate 1: explicit authorization acknowledgment ---------------
    if !cli.i_have_authorization {
        return Err(
            "refusing to run: pass --i-have-authorization to confirm you are authorized \
             to test these targets"
                .to_string(),
        );
    }

    // --- Targets: -p and/or -list ------------------------------------------
    let mut targets: Vec<String> = Vec::new();
    if let Some(ip) = &cli.ip {
        let ip = ip.trim();
        if !ip.is_empty() {
            targets.push(ip.to_string());
        }
    }
    if let Some(file) = &cli.ip_list {
        targets.extend(read_list_file(file, "--ip-list")?);
    }
    dedupe_case_insensitive(&mut targets);
    if targets.is_empty() {
        return Err("no target given: use -p <IP> and/or -list <FILE>".to_string());
    }

    // --- Usernames: -u and/or -ul ------------------------------------------
    let mut usernames: Vec<String> = Vec::new();
    if let Some(user) = &cli.username {
        let user = user.trim();
        if !user.is_empty() {
            usernames.push(user.to_string());
        }
    }
    if let Some(file) = &cli.user_list {
        usernames.extend(read_list_file(file, "--user-list")?);
    }
    if usernames.is_empty() {
        return Err("no usernames given: use -u <USER> and/or -ul <FILE>".to_string());
    }

    // --- Passwords: -pl -----------------------------------------------------
    let mut passwords = read_list_file(&cli.password_list, "--password-list")?;
    dedupe_exact(&mut passwords);
    if passwords.is_empty() {
        return Err("password list is empty".to_string());
    }

    // --- Safety gate 2: private/local refusal, checked for EVERY target -----
    // Done up-front so a single disallowed target refuses the whole batch
    // before any connection is made.
    let mut resolved: Vec<(String, IpAddr)> = Vec::new();
    for target in &targets {
        let addresses = ensure_target_allowed(target, cli.port, cli.allow_private)
            .map_err(|e| format!("{e}"))?;
        let ip = addresses
            .first()
            .expect("resolve_target guarantees at least one address")
            .ip();
        resolved.push((target.clone(), ip));
    }

    // --- One audit run per target ------------------------------------------
    let log_path = cli.log_file.display().to_string();
    let mut overall = EXIT_COMPLETED_NO_FINDING;

    for (target, ip) in resolved {
        eprintln!(
            "\n=== auditing {target} (resolved: {ip}:{}) ===",
            cli.port
        );

        let mut config = AuditConfig {
            target: target.clone(),
            ip,
            port: cli.port,
            usernames: usernames.clone(),
            passwords: passwords.clone(),
            domain: cli.domain.clone(),
            delay: Duration::from_millis(cli.delay),
            max_attempts: cli.max_attempts as usize,
            concurrency: cli.concurrency as usize,
            timeout: Duration::from_secs(cli.timeout),
            log_path: log_path.clone(),
        };
        config.validate().map_err(|e| e.to_string())?;

        let tester =
            RdpTester::new(config, log_path.clone()).map_err(|e| format!("cannot open log file: {e}"))?;
        let summary = tester.run().await;
        print_summary(&summary);

        match exit_code(&summary) {
            EXIT_VALID_FOUND => overall = EXIT_VALID_FOUND,
            EXIT_ABORTED if overall == EXIT_COMPLETED_NO_FINDING => overall = EXIT_ABORTED,
            _ => {}
        }

        // An account lockout is a hard stop for the whole batch: the same
        // account names may exist on the remaining targets, and continuing
        // could lock them out as well.
        if let Some(HaltReason::AccountLockout { username }) = &summary.halted {
            eprintln!(
                "[!] Stopping the whole batch: account '{username}' locked out on {target}. \
                 No further targets will be contacted."
            );
            break;
        }
    }

    Ok(overall)
}

/// Reads a file of one item per line, ignoring blank lines and `#` comments.
fn read_list_file(path: &Path, flag: &str) -> Result<Vec<String>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {flag} {}: {e}", path.display()))?;
    let items: Vec<String> = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();
    if items.is_empty() {
        return Err(format!("{flag} {} contains no entries", path.display()));
    }
    Ok(items)
}

/// De-duplicates while preserving order (case-insensitive: usernames/targets).
fn dedupe_case_insensitive(items: &mut Vec<String>) {
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert(item.to_lowercase()));
}

/// De-duplicates while preserving order (case-sensitive: passwords).
fn dedupe_exact(items: &mut Vec<String>) {
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert(item.clone()));
}

/// Maps an audit summary to the process exit code.
fn exit_code(summary: &AuditSummary) -> u8 {
    if summary.found_valid() {
        EXIT_VALID_FOUND
    } else if summary.halted.is_some() {
        EXIT_ABORTED
    } else {
        EXIT_COMPLETED_NO_FINDING
    }
}

/// Prints the end-of-run report. Full passwords appear only next to confirmed
/// valid credentials; every other line keeps them masked.
fn print_summary(summary: &AuditSummary) {
    println!("\n=========================== audit summary ===========================");
    println!("target          : {}", summary.target);
    println!("attempts used   : {}", summary.attempts_used);
    println!("valid creds     : {}", summary.valid_credentials.len());
    println!(
        "access denied   : {} user(s) without RDP logon right",
        summary.access_denied.len()
    );
    println!(
        "policy restricted: {} user(s)",
        summary.restricted.len()
    );

    if !summary.valid_credentials.is_empty() {
        println!("\n[!] VALID CREDENTIALS FOUND:");
        for credential in &summary.valid_credentials {
            let domain = credential
                .domain
                .as_deref()
                .map(|d| format!("{d}\\"))
                .unwrap_or_default();
            println!("    {}{}:{}", domain, credential.username, credential.password);
        }
    }

    if !summary.access_denied.is_empty() {
        println!("\n[*] authenticated but NOT allowed to use RDP:");
        for username in &summary.access_denied {
            println!("    {username}");
        }
    }

    if !summary.restricted.is_empty() {
        println!("\n[*] restricted accounts (disabled / logon hours / workstation):");
        for username in &summary.restricted {
            println!("    {username}");
        }
    }

    if let Some(halt) = &summary.halted {
        println!("\n[!] RUN ABORTED EARLY: {halt:?}");
    }

    println!("audit log       : {}", summary.log_path);
    println!("=====================================================================");
}
