# rdp-audit

A small, **educational** RDP/NLA (CredSSP) credential-auditing tool written in
Rust for **authorized penetration-test labs**.

It performs real Network Level Authentication attempts through IronRDP's public
connector API — a native Rust implementation, **no external binaries and no
subprocess calls** — and stops as soon as CredSSP delivers a verdict. No RDP
session is ever established.

> ## ⚠️ Legal disclaimer
>
> **FOR AUTHORIZED TESTING ONLY. Unauthorized access is illegal.**
>
> This software exists to help security professionals verify password strength
> and account policies on systems they own or have **explicit written
> permission** to test. Running it against systems you do not own or are not
> authorized to test is a criminal offence in most jurisdictions (e.g. the
> Computer Fraud and Abuse Act in the US, §202a StGB in Germany, the Computer
> Misuse Act in the UK).
>
> The authors accept no liability for misuse or for any damage caused by this
> tool. You are solely responsible for complying with all applicable laws and
> contracts. When in doubt: **do not run it**.

## How it works

1. **TCP connect** to the target port (default 3389).
2. **X.224 negotiation** requesting `PROTOCOL_HYBRID`/`HYBRID_EX` (NLA). If the
   server does not offer NLA, the run is refused instead of falling back to a
   graphical login screen.
3. **TLS upgrade** (certificate verification disabled for lab servers — see
   [Limitations](#limitations)). Modern servers are handled by `rustls`; if the
   handshake is refused because the server only offers legacy RSA key exchange /
   AES-CBC suites, the attempt is repeated with the OS TLS stack (Schannel on
   Windows), exactly like `mstsc` does.
4. **CredSSP (NTLM) exchange** — the NLA-only authentication.
   - `SUCCESS` ⇒ credentials are valid.
   - A server NTSTATUS (e.g. `STATUS_LOGON_FAILURE`, `STATUS_ACCOUNT_LOCKED_OUT`)
     is mapped to a precise verdict.
   - `EarlyUserAuthResult`/`AccessDenied` ⇒ the password is right but the
     account has no Remote Desktop logon right.
5. The session is **abandoned right after CredSSP** — this tool never requests
   an interactive desktop, never joins channels, never touches files.

## Safety rails (mandatory, not configurable away)

| Rail | Behaviour |
|------|-----------|
| Authorization gate | Without `--i-have-authorization` the tool prints the banner and exits with code `1` — nothing is contacted. |
| Private-target refusal | RFC1918, loopback, link-local, CGNAT and IPv6 ULA/link-local targets are refused unless `--allow-private` is given. |
| Lockout abort | On the **first** `ACCOUNT_LOCKED_OUT` every queued and in-flight attempt is cancelled immediately, with a loud warning. |
| Attempt budget | `--max-attempts` (default `50`) is a hard global cap. |
| Rate limiting | `--delay` (default `1000 ms`) paces every worker; a lower value is raised to a 250 ms floor. |
| Concurrency cap | `--concurrency` is limited to `1..=8` (default `2`). |
| Unreachable-target abort | 5 consecutive connection errors stop the run (exit code `4`). |
| Auditing | Every action is appended to a timestamped log file (`--log-file`, default `rdp-audit.log`). Failed passwords are **masked**; only confirmed valid credentials are recorded in clear text. |

## Requirements

- Rust **1.89+** (edition 2021 crate; dependencies are edition 2024).
- A target whose RDP service **offers NLA** (the Windows default since
  Server 2008 R2 / Windows 7).

## Build

```console
cargo build --release
```

The binary is `target/release/rdp-audit`.

## Usage

The interface uses short, single-dash flags:

```text
-p <IP>        one target IP / hostname
-list <FILE>   file with target IPs (one per line)
-u <USER>      one username
-ul <FILE>     file with usernames (one per line)
-pl <FILE>     file with passwords (one per line)
```

All long spellings also work: `--ip`, `--ip-list`, `--username`, `--user-list`,
`--password-list` (plus `--target`, `--user-file`, `--wordlist` aliases).

Single target, single user, one password list:

```console
rdp-audit -p 192.168.174.133 -u testuser -pl passwords.txt --i-have-authorization --allow-private
```

or from the source tree:

```console
cargo run --release -- -p 192.168.174.133 -u testuser -pl passwords.txt --i-have-authorization --allow-private
```

Two passwords for one account simply means a two-line `passwords.txt`:

```text
12323wdw223
12345678
```

Multiple targets, users and passwords (one audit run per target, sequential):

```console
rdp-audit -list targets.txt -ul users.txt -pl passwords.txt --i-have-authorization --allow-private
```

Every input file accepts blank lines and `#` comments.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-p <IP>` / `--ip` | – | One target IP or hostname. |
| `-list <FILE>` / `--ip-list` | – | File with target IPs / hostnames. |
| `-u <USER>` / `--username` | – | One username (may be combined with `-ul`). |
| `-ul <FILE>` / `--user-list` | – | File with usernames. |
| `-pl <FILE>` / `--password-list` | *(required)* | File with passwords. |
| `--port <PORT>` | `3389` | RDP TCP port. |
| `--delay <MS>` | `1000` | Per-worker delay between attempts (minimum 250). |
| `--max-attempts <N>` | `50` | Hard cap on attempts **per target**. |
| `--concurrency <N>` | `2` | Concurrent workers, `1..=8`. |
| `--timeout <SECS>` | `15` | Per-attempt handshake timeout, `5..=120`. |
| `--domain <NAME>` | – | RDP domain / workgroup. |
| `--log-file <FILE>` | `rdp-audit.log` | Timestamped audit log (appended). |
| `--i-have-authorization` | – | **Required.** Confirms you are authorized to test the targets. |
| `--allow-private` | – | Allow private/local (RFC1918, loopback, …) targets. |

Either `-p` or `-list` (or both) must be supplied; either `-u` or `-ul` (or
both) must be supplied.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Run completed; no valid credential found. |
| `1` | Refused: missing authorization flag, private target without `--allow-private`, bad configuration, unreadable input file. |
| `2` | Command-line parsing error (clap). |
| `3` | **Valid credential(s) found** (on at least one target). |
| `4` | Run aborted early: account lockout or unreachable target. |

With `-list`, targets are audited **sequentially**. A valid credential on any
target yields exit code `3`; an account lockout stops the whole batch (the same
account names may exist on the remaining hosts); an unreachable target only
skips that host.

## Interpreting the results

| Log code | Meaning |
|----------|---------|
| `VALID_CREDENTIALS` | CredSSP accepted the credentials. |
| `LOGON_FAILURE` | Wrong username or password (NTSTATUS `LOGON_FAILURE`, `NO_SUCH_USER`, …). |
| `ACCOUNT_LOCKED_OUT` | The account is locked out — the run is aborted. |
| `ACCESS_DENIED` | Password is right, but the account has no Remote Desktop logon right. |
| `PASSWORD_MUST_CHANGE` | The account must change its password at next logon. |
| `ACCOUNT_RESTRICTED` | Account disabled, or logon hours / workstation restrictions. |
| `CONNECTION_ERROR` | TCP/TLS/negotiation failure — not an authentication verdict. |

## Limitations

- **NTLM only.** Kerberos-only environments (where the server requests a KDC
  round-trip) are reported as an error instead of being guessed at. Use
  `--domain` with NTLM-capable servers.
- **TLS certificate verification is disabled.** Lab servers commonly present
  self-signed certificates. CredSSP still binds the authentication to the
  server's public key, but do not treat this tool as a TLS-security oracle.
- **Legacy TLS suites.** `rustls` implements only ECDHE + AEAD suites. RDP
  servers that offer nothing but RSA key exchange with AES-CBC (common on older
  Windows builds) are retried once per target with the OS TLS stack (Schannel on
  Windows). The engine that worked is remembered for the rest of the run.
- **How a rejected logon is reported.** Some Windows builds terminate a failed
  NLA exchange with a fatal TLS `access_denied` alert instead of a CredSSP error
  PDU; that alert is classified as `LOGON_FAILURE`. The precise NTSTATUS (for
  example `ACCOUNT_LOCKED_OUT`) is only available when the server sends the
  CredSSP error PDU, which is why the conservative attempt limits, the per-worker
  delay and the default lockout abort all remain mandatory.
- **NLA-only targets.** Servers without NLA are refused (no graphical-login
  fallback), by design.
- A successful CredSSP exchange does **not** prove the account may open an
  interactive desktop — that is what `ACCESS_DENIED` reports separately.
- Account lockout policy is **not** read from the domain: the tool cannot know
  the threshold in advance, which is exactly why the default delay is 1 s, the
  default budget is small, and the first lockout aborts everything.

## Tests

```console
cargo test
```

The integration tests never touch the network: the engine runs against a
scripted mock backend (`tests/common/mod.rs`) covering valid-credential stops,
lockout aborts, attempt budgets, unreachable targets, access-denied and
restricted-account handling, password masking, the private-target gate, and the
logger format.

## Project layout

```
src/
  main.rs        CLI, authorization/private-target gates, exit codes, report
  lib.rs         crate wiring and re-exports
  rdp_tester.rs  engine (budgets, pacing, lockout abort) + IronRDP NLA backend
  safety.rs      address classification and the --allow-private gate
  logger.rs      timestamped, append-only audit log
tests/
  common/mod.rs  scripted mock backend + helpers
  runner_tests.rs, safety_tests.rs, logger_tests.rs
```

## License

MIT OR Apache-2.0.
