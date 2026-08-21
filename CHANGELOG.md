# Changelog

All notable changes to `dcerpc` will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
project adheres to [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing pending.

## [0.2.6] — 2026-08-20 *(committed local, not yet published)*

### Added
- `fuzz/` — cargo-fuzz workspace with 8 targets: srvsvc_decode,
  wkssvc_decode, samr_enum_domains, samr_lookup_domain,
  lsat_lookup_names, rrp_query_value, rrp_query_info_class,
  rrp_enum_key. libFuzzer only runs on Linux (WSL Kali here).

### Fixed
- `samr::decode_enum_domains` bounded-alloc preflight
  (`entries × 12` vs remaining stub). Discovered by
  `samr_enum_domains` fuzz target within ~15 s of first run;
  regression test uses the exact 24-byte crash artifact.
- `lsat::decode_lookup_names` bounded-alloc preflight
  (`entries × 12` vs remaining stub). Same fuzz-driven discovery path.

## [0.2.5] — 2026-08-20

### Added
- `dcerpc::wkssvc` — MS-WKST `NetrWkstaUserEnum` level 1 client
  (logged-on-user enumeration, needs local admin).
- `dcerpc::rrp::logged_on_sids` — HKU registry walk returning loaded-profile SIDs.

### Fixed
- `wkssvc::decode_wksta_user_enum` — `entries_read × 16` bounded-alloc
  preflight against remaining stub. Regression test with `0xFFFFFFFF`
  input asserts `RpcError::Protocol`.

### Docs
- Stripped third-party tool names from wire-format dev-note comments
  (byte-diff comparison notes rewritten as MS-* spec citations).

## [0.2.4] — 2026-08-18

### Fixed
- Three bounded-alloc preflights closing DoS from hostile `u32`
  attacker-controlled sizes:
  - `srvsvc::decode_session_enum` — `entries_read × 16` preflight.
  - `rrp::decode_query_info_class` — `actual × 2` preflight.
  - `rrp::decode_enum_key` — `actual × 2` preflight.

## [0.2.3] — 2026-08-10

### Fixed
- Dropped `ms-nrpc` reverse-dep to break the `dcerpc ↔ ms-nrpc`
  resolver cycle (0.2.2 was yanked for the same reason). Netlogon
  primitives restored as inline defensive code inside `netlogon.rs`;
  full-fat `ms-nrpc` remains available as standalone.

## [0.2.2] — 2026-08-09 [YANKED]

Yanked due to cyclic version resolution: `ms-nrpc = "0.1.0-dev"` fed
back through `dcerpc = "0.2"` created a resolver loop. Replaced by
0.2.3 which drops the ms-nrpc reverse dep.

## [0.2.1] — 2026-08-06

### Added
- ICPR / DCOM / DCOM-WMI stubs for AD CS + WMI-exec flows.
- Sealed named-pipe bind via NTLM sign+seal.

### Fixed
- Assorted NDR alignment corner cases uncovered by live-DC validation.

## [0.2.0] — 2026-08-02

### Changed
- Extracted NDR marshaling into its own [`ms-ndr`](https://crates.io/crates/ms-ndr)
  crate; `dcerpc` now re-exports via a thin shim for backward compat.
- API surface stabilised on the four primary interfaces
  (SRVSVC / RRP / SAMR / LSAT).

## [0.1.0] — 2026-07-28

Initial release: hand-rolled NDR encoder/decoder, DCE/RPC PDU framing,
NTLMSSP sign+seal transport, EPM port-mapping, initial SRVSVC/SAMR/LSAT/
RRP clients over SMB2 named pipes.
