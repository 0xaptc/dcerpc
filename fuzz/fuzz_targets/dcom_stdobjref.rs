//! Fuzz DCOM OBJREF_STANDARD discovery in activation replies.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::dcom_wmi::parse_stdobjref(data);
});
