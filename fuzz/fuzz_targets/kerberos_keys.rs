//! Fuzz USER_PROPERTIES and KERB_STORED_CREDENTIAL_NEW parsing.

#![no_main]
#![allow(deprecated)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::drsuapi::parse_kerberos_keys(data);
});
