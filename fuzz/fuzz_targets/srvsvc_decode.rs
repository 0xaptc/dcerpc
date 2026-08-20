//! Fuzz `srvsvc::decode_session_enum` against arbitrary attacker-controlled reply stubs.
//!
//! Contract the decoder is expected to hold under every input:
//!   - never panic
//!   - never over-allocate (bounded-alloc preflight is in place since 0.2.5)
//!   - either return `Ok((Vec<Session>, u32, u32))` or an `Err(RpcError::*)`
//!
//! Any panic (index out of bounds, unwrap on None/Err, arithmetic overflow) is a
//! bug. Any `handle_alloc_error` abort is a bounded-alloc regression.
//!
//! Seed corpus: `fuzz/corpus/srvsvc_decode/` — populate with the hand-built
//! replies from `src/srvsvc.rs` tests plus a few truncation variants.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::srvsvc::decode_session_enum(data);
});
