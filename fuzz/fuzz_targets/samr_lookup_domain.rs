//! Fuzz `samr::decode_lookup_domain` — SAMR `SamrLookupDomainInSamServer` reply parser (returns a SID).
//! Contract: never panic, never over-allocate, only Ok/Err. See `fuzz/README.md`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::samr::decode_lookup_domain(data);
});
