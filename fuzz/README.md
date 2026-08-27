# dcerpc fuzz

libFuzzer targets for the crate's externally reachable reply decoders and DCE/RPC framing
boundaries. They complement unit regressions for malformed lengths, bounded allocation, and
authenticated response structure.

## Targets

| Bin | Function under fuzz |
|---|---|
| `srvsvc_decode` | `srvsvc::decode_session_enum` |
| `wkssvc_decode` | `wkssvc::decode_wksta_user_enum` |
| `samr_enum_domains` | `samr::decode_enum_domains` |
| `samr_lookup_domain` | `samr::decode_lookup_domain` |
| `lsat_lookup_names` | `lsat::decode_lookup_names` |
| `rrp_query_value` | `rrp::decode_query_value` |
| `rrp_query_info_class` | `rrp::decode_query_info_class` |
| `rrp_enum_key` | `rrp::decode_enum_key` |
| `pdu_parse` | common header, BIND_ACK, plain and sealed response framing |
| `dcom_stdobjref` | `dcom_wmi::parse_stdobjref` |
| `rprn_status` | `rprn::decode_rffpcnex_status` |
| `icpr_response` | `icpr::decode_cert_server_response` |
| `drsuapi_reply` | `drsuapi::parse_repl_object` |
| `kerberos_keys` | `drsuapi::parse_kerberos_keys` |

## Requirements

- **Rust nightly** — libFuzzer requires the `-Z sanitizer=…` flag family.
- **Linux** — libFuzzer runtime ships with clang; on Windows Git-Bash / MSYS
  the runtime DLL isn't reliably discoverable. WSL Kali / Ubuntu / any Linux
  is the supported fuzz environment.

```bash
# One-time install
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

## Run

```bash
# Time-boxed smoke run — good default for CI + PR checks
cargo fuzz run srvsvc_decode -- -max_total_time=60

# Long overnight run
cargo fuzz run srvsvc_decode -- -max_total_time=28800   # 8h

# Minimize a discovered crash artifact
cargo fuzz tmin srvsvc_decode fuzz/artifacts/srvsvc_decode/crash-...

# Coverage report (nightly + rustc-dev needed)
cargo fuzz coverage srvsvc_decode
```

## Contract every decoder is expected to hold

For every target, **any input** accepted by libFuzzer must:

1. **Never panic** — no `unwrap` / `expect` / arithmetic-overflow / index-out-of-bounds hits.
2. **Never over-allocate** — bounded-alloc preflight rejects hostile `u32` counts before `Vec::with_capacity`.
3. Return either `Ok(<result>)` or `Err(RpcError::*)` — no other exit paths.

A crash artifact under `fuzz/artifacts/<target>/` is a bug. File it as a
GitHub Issue with the artifact attached (or add it to the crate's regression
test suite as a `#[test]`).

## Seed corpus

`fuzz/corpus/<target>/` — each target ships with 2-3 hand-crafted seeds:

- **valid** — a known-good spec-shaped reply extracted from the crate's own
  unit-test fixtures. Anchors the fuzzer to the "normal" grammar so it starts
  exploring outward instead of purely random-bytes.
- **empty** — zero-length input. Every decoder must handle this cleanly.
- **hostile-*** — inputs that model the specific attacker-controlled shapes
  the bounded-alloc preflight guards against (e.g. `entries_read = 0xFFFFFFFF`
  + truncated tail).

## Not in scope

- **Windows-native fuzzing** — libFuzzer's clang runtime is Linux-first. Build
  verification on Windows is fine (`cargo +nightly fuzz build …`), but actual
  runs go through WSL / a Linux CI runner.
- **Network and SSP state machines** — fuzz targets exercise their pure framing boundary;
  asynchronous TCP/SMB I/O and stateful NTLM/Kerberos implementations remain covered by unit,
  integration, and live-lab tests.
- **Symbolic execution / KLEE-style analysis** — libFuzzer's coverage-guided
  mutation is enough given the input surface here (typically ≤ 4 KB per stub).
