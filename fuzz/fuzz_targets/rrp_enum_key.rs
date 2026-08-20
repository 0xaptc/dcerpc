//! Fuzz `rrp::decode_enum_key` — MS-RRP `BaseRegEnumKey` subkey-name reply parser.
//! Contract: never panic, never over-allocate, only Ok/Err. See `fuzz/README.md`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::rrp::decode_enum_key(data);
});
