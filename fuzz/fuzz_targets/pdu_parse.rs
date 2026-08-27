//! Fuzz untrusted DCE/RPC common, plain-response and sealed-response framing.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dcerpc::pdu::parse_header(data);
    let _ = dcerpc::pdu::parse_response(data);
    let _ = dcerpc::pdu::split_sealed_response(data);
    let _ = dcerpc::pdu::parse_bind_ack(data, None);
});
