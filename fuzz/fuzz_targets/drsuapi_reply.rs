//! Fuzz the deprecated in-crate DRSGetNCChanges reply walker.

#![no_main]
#![allow(deprecated)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::drsuapi::parse_repl_object(data);
});
