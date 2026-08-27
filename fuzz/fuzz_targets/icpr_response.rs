//! Fuzz the MS-ICPR CertServerRequest reply decoder.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::icpr::decode_cert_server_response(data);
});
