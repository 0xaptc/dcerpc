//! Fuzz `rrp::decode_query_info_class` — MS-RRP `BaseRegQueryInfoKey` class-name arm.
//! Contract: never panic, never over-allocate, only Ok/Err. See `fuzz/README.md`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::rrp::decode_query_info_class(data);
});
