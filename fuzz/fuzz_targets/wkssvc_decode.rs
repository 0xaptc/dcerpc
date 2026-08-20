//! Fuzz `wkssvc::decode_wksta_user_enum` — MS-WKST `NetrWkstaUserEnum` level-1 reply parser.
//! Contract: never panic, never over-allocate, only Ok/Err. See `fuzz/README.md`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::wkssvc::decode_wksta_user_enum(data);
});
