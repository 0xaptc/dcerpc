//! Connection-oriented DCE/RPC PDUs (MS-RPCE §2.2.6, DCE 1.1 §12.6). Little-endian DREP.

use crate::{ndr_transfer_syntax, Result, RpcError, Syntax};

pub mod ptype {
    pub const REQUEST: u8 = 0;
    pub const RESPONSE: u8 = 2;
    pub const FAULT: u8 = 3;
    pub const BIND: u8 = 11;
    pub const BIND_ACK: u8 = 12;
    pub const BIND_NAK: u8 = 13;
    pub const AUTH3: u8 = 16;
}

/// DCE/RPC authentication (MS-RPCE §2.2.2.11).
///
/// `RPC_C_AUTHN_WINNT` (NTLMSSP) and `RPC_C_AUTHN_GSS_KERBEROS` (SPNEGO/Kerberos AP-REQ)
/// are the two SSPs an on-wire dcerpc client currently emits; the level selects auth-only
/// vs sign+seal.
pub const RPC_C_AUTHN_WINNT: u8 = 0x0a;
pub const RPC_C_AUTHN_GSS_KERBEROS: u8 = 0x10;
pub const RPC_C_AUTHN_LEVEL_PKT_CONNECT: u8 = 0x02;
pub const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u8 = 0x06;

const PFC_FIRST_FRAG: u8 = 0x01;
const PFC_LAST_FRAG: u8 = 0x02;
const DREP_LE: [u8; 4] = [0x10, 0x00, 0x00, 0x00]; // little-endian, ASCII, IEEE float

/// 16-byte common header with `frag_length` patched in after the body is known.
fn header(ptype: u8, frag_length: u16, call_id: u32) -> Vec<u8> {
    header_auth(ptype, frag_length, 0, call_id)
}

/// 16-byte common header carrying a non-zero `auth_length` (length of the auth verifier's
/// auth_value, excluding the 8-byte sec_trailer).
fn header_auth(ptype: u8, frag_length: u16, auth_length: u16, call_id: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(16);
    h.push(5); // rpc_vers
    h.push(0); // rpc_vers_minor
    h.push(ptype);
    h.push(PFC_FIRST_FRAG | PFC_LAST_FRAG);
    h.extend_from_slice(&DREP_LE);
    h.extend_from_slice(&frag_length.to_le_bytes());
    h.extend_from_slice(&auth_length.to_le_bytes());
    h.extend_from_slice(&call_id.to_le_bytes());
    h
}

/// The 8-byte sec_trailer that precedes the auth_value in an authenticated PDU.
fn sec_trailer(auth_pad_length: u8) -> [u8; 8] {
    sec_trailer_lvl(auth_pad_length, RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
}

/// `sec_trailer` with an explicit auth level — needed for relay flows that request
/// `PKT_CONNECT` (auth-only, no per-message signing/sealing), because the relaying attacker
/// doesn't hold the victim's NTLM session key and can't produce signatures.
pub(crate) fn sec_trailer_lvl(auth_pad_length: u8, auth_level: u8) -> [u8; 8] {
    sec_trailer_full(RPC_C_AUTHN_WINNT, auth_level, auth_pad_length)
}

/// `sec_trailer` with explicit auth_type + auth_level — the shared constructor for both the
/// NTLMSSP and Kerberos (`RPC_C_AUTHN_GSS_KERBEROS`) sealed-bind paths. `auth_context_id`
/// is a fixed 0 on this stack; Windows accepts any value on the client leg.
pub(crate) fn sec_trailer_full(auth_type: u8, auth_level: u8, auth_pad_length: u8) -> [u8; 8] {
    [auth_type, auth_level, auth_pad_length, 0, 0, 0, 0, 0]
}

fn bind_body(abstract_syntax: Syntax) -> Vec<u8> {
    let ndr = ndr_transfer_syntax();
    let mut body = Vec::new();
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
    body.push(1); // n_context_elem
    body.push(0);
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    body.push(1); // n_transfer_syn
    body.push(0);
    body.extend_from_slice(&abstract_syntax.uuid);
    body.extend_from_slice(&abstract_syntax.ver_major.to_le_bytes());
    body.extend_from_slice(&abstract_syntax.ver_minor.to_le_bytes());
    body.extend_from_slice(&ndr.uuid);
    body.extend_from_slice(&ndr.ver_major.to_le_bytes());
    body.extend_from_slice(&ndr.ver_minor.to_le_bytes());
    body
}

/// Build a BIND PDU offering one presentation context (abstract syntax + NDR transfer).
pub fn build_bind(call_id: u32, abstract_syntax: Syntax) -> Vec<u8> {
    let body = bind_body(abstract_syntax);
    let frag_length = (16 + body.len()) as u16;
    let mut pdu = header(ptype::BIND, frag_length, call_id);
    pdu.extend_from_slice(&body);
    pdu
}

/// BIND carrying an NTLM auth verifier (the NEGOTIATE token) for a sign+sealed session.
pub fn build_bind_auth(call_id: u32, abstract_syntax: Syntax, auth_token: &[u8]) -> Vec<u8> {
    let body = bind_body(abstract_syntax);
    let frag_length = (16 + body.len() + 8 + auth_token.len()) as u16;
    let mut pdu = header_auth(ptype::BIND, frag_length, auth_token.len() as u16, call_id);
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer(0));
    pdu.extend_from_slice(auth_token);
    pdu
}

/// [`build_bind_auth`] with an explicit auth level. For relay flows we ask for
/// `PKT_CONNECT` (auth-only) so subsequent calls need no per-message signing/sealing —
/// otherwise the middle attacker (who doesn't hold the victim's NTLM session key) can
/// authenticate but can't send any actual RPC calls.
pub fn build_bind_auth_level(
    call_id: u32,
    abstract_syntax: Syntax,
    auth_token: &[u8],
    auth_level: u8,
) -> Vec<u8> {
    let body = bind_body(abstract_syntax);
    let frag_length = (16 + body.len() + 8 + auth_token.len()) as u16;
    let mut pdu = header_auth(ptype::BIND, frag_length, auth_token.len() as u16, call_id);
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer_lvl(0, auth_level));
    pdu.extend_from_slice(auth_token);
    pdu
}

/// [`build_auth3`] with an explicit auth level (see [`build_bind_auth_level`]).
pub fn build_auth3_level(call_id: u32, auth_token: &[u8], auth_level: u8) -> Vec<u8> {
    let frag_length = (16 + 4 + 8 + auth_token.len()) as u16;
    let mut pdu = header_auth(ptype::AUTH3, frag_length, auth_token.len() as u16, call_id);
    pdu.extend_from_slice(&[0, 0, 0, 0]);
    pdu.extend_from_slice(&sec_trailer_lvl(0, auth_level));
    pdu.extend_from_slice(auth_token);
    pdu
}

/// AUTH3 PDU carrying the NTLM AUTHENTICATE token — the final leg of the bind handshake.
pub fn build_auth3(call_id: u32, auth_token: &[u8]) -> Vec<u8> {
    // rpcconn_auth3: common header, a 4-byte pad (max_xmit/recv, ignored), then the verifier.
    let frag_length = (16 + 4 + 8 + auth_token.len()) as u16;
    let mut pdu = header_auth(ptype::AUTH3, frag_length, auth_token.len() as u16, call_id);
    pdu.extend_from_slice(&[0, 0, 0, 0]);
    pdu.extend_from_slice(&sec_trailer(0));
    pdu.extend_from_slice(auth_token);
    pdu
}

/// BIND carrying a SPNEGO / Kerberos AP-REQ token (auth_type = `RPC_C_AUTHN_GSS_KERBEROS`).
///
/// The token itself is the GSS-API `InitialContextToken(SPNEGO → negTokenInit → krb5(AP-REQ))`
/// blob — built by a Kerberos crate holding the TGS session key. This function only frames it
/// as an RPC BIND with the given auth level (PKT_PRIVACY for sealed sessions).
pub fn build_bind_auth_kerberos(
    call_id: u32,
    abstract_syntax: Syntax,
    ap_req_gss_token: &[u8],
    auth_level: u8,
) -> Vec<u8> {
    let body = bind_body(abstract_syntax);
    let frag_length = (16 + body.len() + 8 + ap_req_gss_token.len()) as u16;
    let mut pdu = header_auth(
        ptype::BIND,
        frag_length,
        ap_req_gss_token.len() as u16,
        call_id,
    );
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer_full(RPC_C_AUTHN_GSS_KERBEROS, auth_level, 0));
    pdu.extend_from_slice(ap_req_gss_token);
    pdu
}

/// AUTH3 PDU completing a Kerberos bind. Windows normally answers BIND_ACK carrying an
/// AP-REP (mutual auth) and the client responds with an empty AUTH3 to close the exchange;
/// pass `&[]` for the empty case, or a follow-up token if one is required.
pub fn build_auth3_kerberos(call_id: u32, auth_token: &[u8], auth_level: u8) -> Vec<u8> {
    let frag_length = (16 + 4 + 8 + auth_token.len()) as u16;
    let mut pdu = header_auth(ptype::AUTH3, frag_length, auth_token.len() as u16, call_id);
    pdu.extend_from_slice(&[0, 0, 0, 0]);
    pdu.extend_from_slice(&sec_trailer_full(RPC_C_AUTHN_GSS_KERBEROS, auth_level, 0));
    pdu.extend_from_slice(auth_token);
    pdu
}

/// The NTLM auth_value (CHALLENGE on a BIND_ACK) is the trailing `auth_length` bytes.
pub fn extract_auth_value(buf: &[u8]) -> Result<Vec<u8>> {
    if buf.len() < 12 {
        return Err(RpcError::Underrun { need: 12, pos: 0 });
    }
    let auth_length = u16::from_le_bytes([buf[10], buf[11]]) as usize;
    if auth_length == 0 || auth_length > buf.len() {
        return Err(RpcError::Protocol(
            "BIND_ACK carried no auth verifier".into(),
        ));
    }
    Ok(buf[buf.len() - auth_length..].to_vec())
}

/// Build a REQUEST PDU carrying an NDR-marshaled stub for `opnum`.
pub fn build_request(call_id: u32, p_cont_id: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + stub.len());
    body.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
    body.extend_from_slice(&p_cont_id.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(stub);

    let frag_length = (16 + body.len()) as u16;
    let mut pdu = header(ptype::REQUEST, frag_length, call_id);
    pdu.extend_from_slice(&body);
    pdu
}

/// Build a sign+sealed REQUEST PDU. `sealed_stub` is the already-RC4-sealed (stub‖pad),
/// `pad_len` the pad it contains, and `signature` the 16-byte NTLM MAC over the plaintext.
/// The request header fields (alloc_hint/cont_id/opnum) travel in the clear.
pub fn build_request_sealed(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    sealed_stub: &[u8],
    pad_len: u8,
    signature: &[u8],
    alloc_hint: u32,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + sealed_stub.len());
    body.extend_from_slice(&alloc_hint.to_le_bytes());
    body.extend_from_slice(&p_cont_id.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(sealed_stub);

    let frag_length = (16 + body.len() + 8 + signature.len()) as u16;
    let mut pdu = header_auth(ptype::REQUEST, frag_length, signature.len() as u16, call_id);
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer(pad_len));
    pdu.extend_from_slice(signature);
    pdu
}

/// As [`build_request_sealed`] but an ORPC (DCOM object) request: sets `PFC_OBJECT_UUID` and inserts
/// the 16-byte object UUID (the target interface's IPID) between the opnum and the stub. The stub
/// therefore begins at offset 40 (header 16 + alloc_hint 4 + p_cont_id 2 + opnum 2 + object 16).
#[allow(clippy::too_many_arguments)]
pub fn build_request_sealed_object(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    object: &[u8; 16],
    sealed_stub: &[u8],
    pad_len: u8,
    signature: &[u8],
    alloc_hint: u32,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(24 + sealed_stub.len());
    body.extend_from_slice(&alloc_hint.to_le_bytes());
    body.extend_from_slice(&p_cont_id.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(object); // ORPC object UUID (IPID)
    body.extend_from_slice(sealed_stub);

    let frag_length = (16 + body.len() + 8 + signature.len()) as u16;
    let mut pdu = header_auth(ptype::REQUEST, frag_length, signature.len() as u16, call_id);
    pdu[3] |= 0x80; // PFC_OBJECT_UUID
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer(pad_len));
    pdu.extend_from_slice(signature);
    pdu
}

/// Build a sign+sealed REQUEST PDU for a Kerberos-authenticated session. Layout matches
/// [`build_request_sealed`] but the sec_trailer carries `RPC_C_AUTHN_GSS_KERBEROS`, and
/// `auth_value` is variable-length (28 B for AES-CTS-HMAC-SHA1-96 DCE-style: 16 B WRAP
/// header + 12 B checksum) rather than NTLM's fixed 16 B.
pub fn build_request_sealed_krb(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    sealed_stub: &[u8],
    pad_len: u8,
    auth_value: &[u8],
    alloc_hint: u32,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + sealed_stub.len());
    body.extend_from_slice(&alloc_hint.to_le_bytes());
    body.extend_from_slice(&p_cont_id.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(sealed_stub);

    let frag_length = (16 + body.len() + 8 + auth_value.len()) as u16;
    let mut pdu = header_auth(
        ptype::REQUEST,
        frag_length,
        auth_value.len() as u16,
        call_id,
    );
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer_full(
        RPC_C_AUTHN_GSS_KERBEROS,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        pad_len,
    ));
    pdu.extend_from_slice(auth_value);
    pdu
}

/// Split a sealed RESPONSE into (sealed_stub‖pad, signature), stripping the sec_trailer.
/// The caller unseals the stub and drops `auth_pad_length` trailing pad bytes.
pub fn split_sealed_response(buf: &[u8]) -> Result<(Vec<u8>, Vec<u8>, u8)> {
    let h = parse_header(buf)?;
    if h.ptype == ptype::FAULT {
        let status = buf
            .get(24..28)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0);
        return Err(RpcError::Fault(status));
    }
    if h.ptype != ptype::RESPONSE {
        return Err(RpcError::UnexpectedPdu(h.ptype));
    }
    let auth_length = u16::from_le_bytes([buf[10], buf[11]]) as usize;
    let frag = (h.frag_length as usize).min(buf.len());
    if frag < 24 + 8 + auth_length {
        return Err(RpcError::Underrun {
            need: 24 + 8 + auth_length,
            pos: frag,
        });
    }
    let stub_start = 24; // header(16) + alloc_hint(4) + cont_id(2) + cancel/reserved(2)
    let sec_trailer_start = frag - 8 - auth_length;
    let pad_len = buf[sec_trailer_start + 2];
    let sealed = buf[stub_start..sec_trailer_start].to_vec();
    let signature = buf[frag - auth_length..frag].to_vec();
    Ok((sealed, signature, pad_len))
}

/// Parsed common header.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub ptype: u8,
    pub frag_length: u16,
    pub call_id: u32,
}

pub fn parse_header(buf: &[u8]) -> Result<Header> {
    if buf.len() < 16 {
        return Err(RpcError::Underrun { need: 16, pos: 0 });
    }
    if buf[0] != 5 {
        return Err(RpcError::Protocol(format!("rpc_vers {} != 5", buf[0])));
    }
    Ok(Header {
        ptype: buf[2],
        frag_length: u16::from_le_bytes([buf[8], buf[9]]),
        call_id: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
    })
}

/// Confirm a BIND_ACK (or surface a BIND_NAK). We do not parse per-context results here;
/// a NAK is fatal and an ACK is sufficient to proceed. On NAK the 2-byte reject_reason
/// (BIND_NAK body offset 0) is captured into `RpcError::Protocol` so callers can see
/// exactly which reject the server sent — spec-decodable reasons (RFC 3.3.1 table):
///   0: reason_not_specified · 1: temporary_congestion · 2: local_limit_exceeded
///   3: called_paddr_unknown · 4: protocol_version_not_supported
///   5: default_context_not_supported · 6: user_data_not_readable
///   7: no_psap_available · 8: authentication_type_not_recognized
///   9: invalid_checksum
pub fn expect_bind_ack(buf: &[u8]) -> Result<()> {
    let h = parse_header(buf)?;
    match h.ptype {
        ptype::BIND_ACK => Ok(()),
        ptype::BIND_NAK => {
            let reason = buf
                .get(16..18)
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()));
            Err(RpcError::Protocol(match reason {
                Some(r) => format!("BIND_NAK reject_reason={r}"),
                None => "BIND_NAK (no reason field)".to_string(),
            }))
        }
        other => Err(RpcError::UnexpectedPdu(other)),
    }
}

/// Extract the stub data from a RESPONSE PDU, or translate a FAULT into an error.
/// Response layout: 16-byte header + alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1).
pub fn parse_response(buf: &[u8]) -> Result<Vec<u8>> {
    let h = parse_header(buf)?;
    match h.ptype {
        ptype::RESPONSE => {
            let start = 24.min(buf.len());
            let end = (h.frag_length as usize).min(buf.len());
            Ok(buf[start..end].to_vec())
        }
        ptype::FAULT => {
            // fault: header + alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1) + status(4)
            let status = buf
                .get(24..28)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            Err(RpcError::Fault(status))
        }
        other => Err(RpcError::UnexpectedPdu(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_header_shape() {
        let samr = Syntax::new("12345778-1234-abcd-ef00-0123456789ac", 1, 0);
        let pdu = build_bind(1, samr);
        assert_eq!(pdu[0], 5); // rpc_vers
        assert_eq!(pdu[2], ptype::BIND);
        assert_eq!(pdu[3], PFC_FIRST_FRAG | PFC_LAST_FRAG);
        let frag = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
        assert_eq!(frag, pdu.len());
        let h = parse_header(&pdu).unwrap();
        assert_eq!(h.ptype, ptype::BIND);
        assert_eq!(h.call_id, 1);
    }

    #[test]
    fn request_carries_opnum_and_stub() {
        let stub = [0xDE, 0xAD, 0xBE, 0xEF];
        let pdu = build_request(7, 0, 0x0005, &stub);
        assert_eq!(pdu[2], ptype::REQUEST);
        // opnum sits at header(16) + alloc_hint(4) + p_cont_id(2) = offset 22
        assert_eq!(u16::from_le_bytes([pdu[22], pdu[23]]), 0x0005);
        assert_eq!(&pdu[24..28], &stub);
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
    }

    #[test]
    fn bind_auth_carries_verifier() {
        let drs = Syntax::new("e3514235-4b06-11d1-ab04-00c04fc2dcd2", 4, 0);
        let token = [0xAAu8; 40];
        let pdu = build_bind_auth(3, drs, &token);
        assert_eq!(pdu[2], ptype::BIND);
        assert_eq!(u16::from_le_bytes([pdu[10], pdu[11]]), token.len() as u16); // auth_length
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len()); // frag_length
                                                                              // sec_trailer sits right before the token: auth_type=WINNT, level=PKT_PRIVACY.
        let st = pdu.len() - token.len() - 8;
        assert_eq!(pdu[st], RPC_C_AUTHN_WINNT);
        assert_eq!(pdu[st + 1], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
        assert_eq!(&pdu[pdu.len() - token.len()..], &token);
        // extract_auth_value recovers the token (models pulling the CHALLENGE off a BIND_ACK).
        assert_eq!(extract_auth_value(&pdu).unwrap(), token);
    }

    #[test]
    fn auth3_shape() {
        let token = [0xBBu8; 120];
        let pdu = build_auth3(4, &token);
        assert_eq!(pdu[2], ptype::AUTH3);
        assert_eq!(u16::from_le_bytes([pdu[10], pdu[11]]), token.len() as u16);
        assert_eq!(&pdu[16..20], &[0, 0, 0, 0]); // the 4-byte pad
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
    }

    #[test]
    fn sealed_request_response_split_roundtrips() {
        let sealed = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let sig = [0x09u8; 16];
        let req = build_request_sealed(9, 0, 3, &sealed, 0, &sig, sealed.len() as u32);
        assert_eq!(req[2], ptype::REQUEST);
        assert_eq!(u16::from_le_bytes([req[10], req[11]]), 16); // auth_length = signature
        assert_eq!(u16::from_le_bytes([req[8], req[9]]) as usize, req.len());
        // Turn it into a RESPONSE shape and split it back.
        let mut resp = req.clone();
        resp[2] = ptype::RESPONSE;
        let (s, g, pad) = split_sealed_response(&resp).unwrap();
        assert_eq!(s, sealed);
        assert_eq!(g, sig);
        assert_eq!(pad, 0);
    }

    #[test]
    fn bind_auth_kerberos_marks_gss_type() {
        let drs = Syntax::new("e3514235-4b06-11d1-ab04-00c04fc2dcd2", 4, 0);
        // Realistic AP-REQ SPNEGO wrapper is ~1.4 KB; a 900-byte placeholder is enough to
        // exercise the auth_length + sec_trailer plumbing.
        let token = vec![0xC5u8; 900];
        let pdu = build_bind_auth_kerberos(9, drs, &token, RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
        assert_eq!(pdu[2], ptype::BIND);
        assert_eq!(u16::from_le_bytes([pdu[10], pdu[11]]), token.len() as u16);
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
        let st = pdu.len() - token.len() - 8;
        assert_eq!(pdu[st], RPC_C_AUTHN_GSS_KERBEROS);
        assert_eq!(pdu[st + 1], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
        assert_eq!(&pdu[pdu.len() - token.len()..], &token[..]);
    }

    #[test]
    fn auth3_kerberos_carries_gss_type() {
        // A completing AUTH3 for Kerberos can legitimately be empty (the AP-REP came in the
        // BIND_ACK and no further token is needed); verify the frame is well-formed anyway.
        let pdu = build_auth3_kerberos(11, &[], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
        assert_eq!(pdu[2], ptype::AUTH3);
        assert_eq!(u16::from_le_bytes([pdu[10], pdu[11]]), 0);
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
        // sec_trailer sits right after the 4-byte pad.
        assert_eq!(pdu[20], RPC_C_AUTHN_GSS_KERBEROS);
        assert_eq!(pdu[21], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
    }

    #[test]
    fn request_sealed_krb_variable_auth_len() {
        // AES-CTS-HMAC-SHA1-96 DCE-style: 16 B WRAP header + 12 B HMAC = 28 B auth_value —
        // wider than NTLM's fixed 16 B, so the framer must respect the passed length.
        let sealed = [0xEEu8; 12];
        let auth_value = [0x77u8; 28];
        let req = build_request_sealed_krb(3, 0, 0x1234, &sealed, 0, &auth_value, 12);
        assert_eq!(req[2], ptype::REQUEST);
        assert_eq!(u16::from_le_bytes([req[10], req[11]]), 28);
        assert_eq!(u16::from_le_bytes([req[8], req[9]]) as usize, req.len());
        // sec_trailer sits between the stub and the auth_value.
        let st = req.len() - auth_value.len() - 8;
        assert_eq!(req[st], RPC_C_AUTHN_GSS_KERBEROS);
        assert_eq!(req[st + 1], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
        assert_eq!(&req[req.len() - auth_value.len()..], &auth_value[..]);
    }

    #[test]
    fn parse_response_extracts_stub() {
        // Fake a RESPONSE: 24-byte prefix then stub.
        let mut pdu = build_request(1, 0, 0, &[]); // reuse header shape
        pdu[2] = ptype::RESPONSE;
        pdu.truncate(16);
        pdu.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // alloc_hint+cont+cancel+reserved
        pdu.extend_from_slice(&[0x11, 0x22]); // stub
        let frag = pdu.len() as u16;
        pdu[8..10].copy_from_slice(&frag.to_le_bytes());
        assert_eq!(parse_response(&pdu).unwrap(), vec![0x11, 0x22]);
    }
}
