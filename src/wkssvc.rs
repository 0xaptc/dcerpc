//! WKSSVC (MS-WKST) — `NetrWkstaUserEnum` over the `\wkssvc` named pipe.
//!
//! Complements SRVSVC: where `NetrSessionEnum` enumerates *incoming* SMB sessions,
//! `NetrWkstaUserEnum` (level 1) enumerates **all LSA logon sessions** on the machine —
//! interactive, service accounts, scheduled tasks, RunAs, and cached network logons.
//! Fields: username, logon domain, other domains, and the authenticating DC.
//! Note: `logon_server` may be a NetBIOS name, an FQDN, empty, or the workstation
//! name itself depending on the session type and Windows version.

use crate::ndr::{NdrDecoder, NdrEncoder};
use crate::transport::SmbPipe;
use crate::{Result, Syntax};
use smb2_client::SmbClient;

/// The WKSSVC interface, v1.0.
pub fn wkssvc_syntax() -> Syntax {
    Syntax::new("6bffd098-a112-3610-9833-46c3f87e345a", 1, 0)
}

pub mod opnum {
    pub const NETR_WKSTA_USER_ENUM: u16 = 2;
}

const WKSTA_USER_LEVEL_1: u32 = 1;

/// One entry from `NetrWkstaUserEnum` level 1 (`WKSTA_USER_INFO_1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WkstaUser {
    /// Logged-on username (`wkui1_username`).
    pub username: String,
    /// Domain the account authenticated against (`wkui1_logon_domain`).
    pub logon_domain: String,
    /// Other domains the workstation is joined to (`wkui1_oth_domains`).
    pub other_domains: String,
    /// Domain controller that authenticated the user (`wkui1_logon_server`).
    pub logon_server: String,
}

/// Marshal a `NetrWkstaUserEnum(ServerName=NULL, Level=1)` request.
/// Wire layout mirrors `encode_session_enum` in `srvsvc.rs`.
pub fn encode_wksta_user_enum() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.null_ptr(); // ServerName [in,string,unique] = NULL

    // WKSTA_USER_ENUM_STRUCT { Level; [switch_is(Level)] WKSTA_USER_ENUM_UNION }
    e.u32(WKSTA_USER_LEVEL_1); // Level
    e.u32(WKSTA_USER_LEVEL_1); // union discriminant (mirrors Level, per NDR)
    e.referent(); // LPWKSTA_USER_INFO_1_CONTAINER (non-null on input)
    e.u32(0); //   EntriesRead = 0
    e.null_ptr(); //   Buffer = NULL

    e.u32(0xFFFF_FFFF); // PreferredMaximumLength (MAX_PREFERRED_LENGTH)
    e.null_ptr(); // ResumeHandle [in,out,unique] = NULL (single-shot)
    e.into_bytes()
}

/// Parse a `NetrWkstaUserEnum` level-1 reply.
/// Returns (users, total_entries, return_code).
/// NDR walk — fixed referents then deferred strings — mirrors `decode_session_enum`
/// in `srvsvc.rs`, extended to four string fields.
pub fn decode_wksta_user_enum(stub: &[u8]) -> Result<(Vec<WkstaUser>, u32, u32)> {
    let mut d = NdrDecoder::new(stub);
    let _level = d.u32()?; // Level (echoed)
    let _tag = d.u32()?; // union discriminant
    let container_ref = d.u32()?; // level-1 container [ref]
    let mut users = Vec::new();
    if container_ref != 0 {
        let entries_read = d.u32()? as usize;
        let buffer_ref = d.u32()?;
        if buffer_ref != 0 {
            let _max = d.u32()?; // conformant max_count
                                 // Fixed parts: EntriesRead × 4 string pointers — 16 wire bytes per entry.
                                 // Bound `entries_read` (attacker-controlled u32) against the remaining stub
                                 // before `Vec::with_capacity` so a hostile server sending
                                 // `entries_read = 0xFFFFFFFF` + a truncated tail can't force a multi-GB
                                 // allocation that aborts via `handle_alloc_error`. Same pattern as the
                                 // rrp.rs sibling sites and srvsvc.rs — see CLAUDE.md "Bounded-alloc pattern".
            if entries_read
                .checked_mul(16)
                .map_or(true, |need| need > d.remaining())
            {
                return Err(crate::RpcError::Protocol(format!(
                    "NetrWkstaUserEnum: EntriesRead={entries_read} exceeds remaining stub"
                )));
            }
            let mut refs = Vec::with_capacity(entries_read);
            for _ in 0..entries_read {
                let user_ref = d.u32()?;
                let logon_domain_ref = d.u32()?;
                let oth_domains_ref = d.u32()?;
                let logon_server_ref = d.u32()?;
                refs.push((
                    user_ref,
                    logon_domain_ref,
                    oth_domains_ref,
                    logon_server_ref,
                ));
            }
            // Deferred parts: each string, in field order, when the referent is non-null.
            for (u_ref, ld_ref, od_ref, ls_ref) in refs {
                let username = if u_ref != 0 {
                    d.conformant_varying_wstr()?
                } else {
                    String::new()
                };
                let logon_domain = if ld_ref != 0 {
                    d.conformant_varying_wstr()?
                } else {
                    String::new()
                };
                let other_domains = if od_ref != 0 {
                    d.conformant_varying_wstr()?
                } else {
                    String::new()
                };
                let logon_server = if ls_ref != 0 {
                    d.conformant_varying_wstr()?
                } else {
                    String::new()
                };
                users.push(WkstaUser {
                    username,
                    logon_domain,
                    other_domains,
                    logon_server,
                });
            }
        }
    }
    let total_entries = d.u32()?;
    // ResumeHandle [in,out,unique]: a referent, then the value if non-null.
    let resume_ref = d.u32()?;
    if resume_ref != 0 {
        let _resume = d.u32();
    }
    let ret = d.u32()?;
    Ok((users, total_entries, ret))
}

/// High-level WKSSVC client bound over `\wkssvc`.
pub struct WkstaUserClient<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> WkstaUserClient<'a> {
    pub async fn bind(client: &'a mut SmbClient, file_id: [u8; 16]) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind(wkssvc_syntax()).await?;
        Ok(WkstaUserClient { pipe })
    }

    /// Enumerate logged-on users (level 1). A non-zero return code
    /// (e.g. 5 = ERROR_ACCESS_DENIED if not local admin) is surfaced to the caller.
    pub async fn enum_users(&mut self) -> Result<(Vec<WkstaUser>, u32)> {
        let resp = self
            .pipe
            .call(opnum::NETR_WKSTA_USER_ENUM, &encode_wksta_user_enum())
            .await?;
        let (users, _total, ret) = decode_wksta_user_enum(&resp)?;
        Ok((users, ret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_selects_level_1_with_null_server() {
        let stub = encode_wksta_user_enum();
        assert_eq!(&stub[0..4], &0u32.to_le_bytes()); // ServerName NULL
        assert_eq!(u32::from_le_bytes(stub[4..8].try_into().unwrap()), 1); // Level
        assert_eq!(u32::from_le_bytes(stub[8..12].try_into().unwrap()), 1); // union tag
    }

    // Hand-built (spec-shaped, NOT symmetric with the encoder) reply carrying one
    // user: CORP\alice logged on from \\DC01.  Validates the decoder's NDR walk
    // against the MS-WKST layout, including a NULL other_domains referent.
    #[test]
    fn decodes_one_user_from_a_handbuilt_reply() {
        fn wstr(out: &mut Vec<u8>, s: &str) {
            let units: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
            out.extend_from_slice(&(units.len() as u32).to_le_bytes()); // max_count
            out.extend_from_slice(&0u32.to_le_bytes()); // offset
            out.extend_from_slice(&(units.len() as u32).to_le_bytes()); // actual_count
            for u in units {
                out.extend_from_slice(&u.to_le_bytes());
            }
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }

        let mut r = Vec::new();
        r.extend_from_slice(&1u32.to_le_bytes()); // Level
        r.extend_from_slice(&1u32.to_le_bytes()); // union tag
        r.extend_from_slice(&0x2_0000u32.to_le_bytes()); // container ref
        r.extend_from_slice(&1u32.to_le_bytes()); // EntriesRead
        r.extend_from_slice(&0x2_0004u32.to_le_bytes()); // Buffer ref
        r.extend_from_slice(&1u32.to_le_bytes()); // conformant max_count
                                                  // WKSTA_USER_INFO_1: 4 string pointers
        r.extend_from_slice(&0x2_0008u32.to_le_bytes()); // username ref
        r.extend_from_slice(&0x2_000cu32.to_le_bytes()); // logon_domain ref
        r.extend_from_slice(&0u32.to_le_bytes()); // other_domains ref = NULL
        r.extend_from_slice(&0x2_0010u32.to_le_bytes()); // logon_server ref
        wstr(&mut r, "alice"); // deferred username
        wstr(&mut r, "CORP"); // deferred logon_domain
        wstr(&mut r, "DC01"); // deferred logon_server (other_domains skipped — NULL referent)
        r.extend_from_slice(&1u32.to_le_bytes()); // TotalEntries
        r.extend_from_slice(&0u32.to_le_bytes()); // ResumeHandle ref = NULL
        r.extend_from_slice(&0u32.to_le_bytes()); // return code

        let (users, total, ret) = decode_wksta_user_enum(&r).unwrap();
        assert_eq!(ret, 0);
        assert_eq!(total, 1);
        assert_eq!(
            users,
            vec![WkstaUser {
                username: "alice".into(),
                logon_domain: "CORP".into(),
                other_domains: String::new(),
                logon_server: "DC01".into(),
            }]
        );
    }

    #[test]
    fn empty_reply_is_not_a_panic() {
        for cut in 0..24 {
            let _ = decode_wksta_user_enum(&vec![0u8; cut]);
        }
    }

    // Hostile server: valid header + non-null container + non-null buffer, then a
    // maliciously large EntriesRead + truncated body. Must return Err(Protocol) —
    // NOT `Vec::with_capacity(0xFFFFFFFF)` → ~64 GB alloc / handle_alloc_error abort.
    #[test]
    fn entries_read_is_bounded_against_stub() {
        let mut r = Vec::new();
        r.extend_from_slice(&1u32.to_le_bytes()); // Level
        r.extend_from_slice(&1u32.to_le_bytes()); // union tag
        r.extend_from_slice(&0x2_0000u32.to_le_bytes()); // container ref
        r.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // EntriesRead = u32::MAX
        r.extend_from_slice(&0x2_0004u32.to_le_bytes()); // Buffer ref
        r.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // conformant max_count
                                                            // (server truncates here)
        let err = decode_wksta_user_enum(&r).unwrap_err();
        assert!(
            matches!(err, crate::RpcError::Protocol(ref s) if s.contains("EntriesRead")),
            "expected Protocol(EntriesRead …), got {err:?}"
        );
    }
}
