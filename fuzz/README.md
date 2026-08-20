# dcerpc fuzz

libFuzzer-based fuzz targets for every top-level reply decoder in the crate.
Complements the unit-test fixtures + the bounded-alloc preflight regressions
that shipped in `dcerpc 0.2.5`.

## Targets

| Bin | Function under fuzz |
|---|---|
| `srvsvc_decode` | `srvsvc::decode_session_enum` |

*(more targets land in v1.3.10 — `wkssvc_decode`, `samr_decode_*`, `lsat_decode`, `netlogon_decode`, `rrp_decode_*`, `svcctl_decode`, `tsch_decode`)*

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

For every reply-decoder fuzz target, **any input** (up to `MAX_INPUT_LEN`) must:

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
- **Non-reply-decoder targets** — the encoder side is fuzz-tested implicitly
  by round-tripping through decoders. Explicit encoder fuzz would help only
  once we add builders that accept caller-controlled untrusted input.
- **Symbolic execution / KLEE-style analysis** — libFuzzer's coverage-guided
  mutation is enough given the input surface here (typically ≤ 4 KB per stub).
