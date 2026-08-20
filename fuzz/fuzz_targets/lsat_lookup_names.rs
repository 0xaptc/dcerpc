//! Fuzz `lsat::decode_lookup_names` — LSAT `LsarLookupNames` reply parser (name → SID resolution).
//! Contract: never panic, never over-allocate, only Ok/Err. See `fuzz/README.md`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::lsat::decode_lookup_names(data);
});
