//! Fuzz the RFFPCNEx reply-status decoder.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::rprn::decode_rffpcnex_status(data);
});
