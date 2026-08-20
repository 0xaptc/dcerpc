//! DCOM (MS-DCOM) — the foundation for remote activation and WMI execution over ORPC.
//!
//! **Status: foundation layer.** This implements the OXID-resolver interface
//! (`IObjectExporter`, a plain RPC interface reachable anonymously on TCP/135) and the shared
//! ORPC pieces (well-known IIDs/CLSIDs, the `ORPCTHIS` header every ORPC call carries). The full
//! WMI-exec chain that builds on this — `ISystemActivator::RemoteCreateInstance` with the
//! activation-properties blob, OXID resolution to the activated object's dynamic endpoint,
//! `IWbemLevel1Login::NTLMLogin`, and `IWbemServices::ExecMethod` for `Win32_Process.Create`
//! with CIM-object marshaling — is not implemented yet. See the module tests + the roadmap.

use crate::ndr::NdrEncoder;
use crate::transport::RpcTcp;
use crate::{Result, RpcError, Syntax};

/// IObjectExporter (the OXID resolver / ping interface), always on ncacn_ip_tcp:135.
pub const IID_IOBJECT_EXPORTER: &str = "99fcfec4-5260-101b-bbcb-00aa0021347a";
/// ISystemActivator — `RemoteCreateInstance` (opnum 4) activates a class on the target.
pub const IID_ISYSTEM_ACTIVATOR: &str = "000001a0-0000-0000-c000-000000000046";
/// IRemUnknown — remote reference counting on an activated object (opnums RemQueryInterface=3…).
pub const IID_IREMUNKNOWN: &str = "00000131-0000-0000-c000-000000000046";
/// IWbemLevel1Login — `NTLMLogin` hands back an `IWbemServices` pointer for a namespace.
pub const IID_IWBEM_LEVEL1_LOGIN: &str = "f309ad18-d86a-11d0-a075-00c04fb68820";
/// IWbemServices — `GetObject` / `ExecMethod` (Win32_Process.Create lives here).
pub const IID_IWBEM_SERVICES: &str = "9556dc99-828c-11cf-a37e-00aa003240c7";
/// CLSID of the WBEM level-1 login object to activate on the target.
pub const CLSID_WBEM_LEVEL1_LOGIN: &str = "8bc3f05e-d86b-11d0-a075-00c04fb68820";

/// ORPC minor version negotiated by current Windows (COMVERSION 5.7).
pub const COMVERSION_MAJOR: u16 = 5;
pub const COMVERSION_MINOR: u16 = 7;

/// Encode an `ORPCTHIS` (MS-DCOM 2.2.13.4) — the header every ORPC method stub begins with,
/// ahead of the interface's own parameters. `cid` is the causality id (a GUID identifying the
/// logical call chain). Layout: COMVERSION(4) · flags(4) · reserved(4) · CID(16) · extensions
/// pointer(4, null) = 32 bytes.
pub fn orpc_this(cid: &[u8; 16]) -> Vec<u8> {
    orpc_this_flags(cid, 1)
}

/// ORPCTHIS with an explicit `flags` word: 1 on the activation call
/// (`RemoteCreateInstance`), 0 on ordinary ORPC method calls (NTLMLogin, ExecMethod, …).
pub fn orpc_this_flags(cid: &[u8; 16], flags: u32) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.u16(COMVERSION_MAJOR);
    e.u16(COMVERSION_MINOR);
    e.u32(flags);
    e.u32(0); // reserved1
    e.uuid(cid); // CID (causality id)
    e.null_ptr(); // ORPC_EXTENT_ARRAY* extensions (none)
    e.into_bytes()
}

/// The IObjectExporter (OXID resolver) client on TCP/135. This is the reachable, anonymous entry
/// point to a host's DCOM subsystem and the resolver that later turns an OXID into the dynamic
/// endpoint of an activated object.
pub struct ObjectExporter {
    rpc: RpcTcp,
}

impl ObjectExporter {
    /// Connect to the OXID resolver and bind IObjectExporter. `host` may be a bare host/IP
    /// (defaults to :135) or `host:port`.
    pub async fn connect(host: &str) -> Result<Self> {
        let addr = if host.contains(':') {
            host.to_string()
        } else {
            format!("{host}:135")
        };
        let mut rpc = RpcTcp::connect(&addr).await?;
        rpc.bind(Syntax::new(IID_IOBJECT_EXPORTER, 0, 0)).await?;
        Ok(ObjectExporter { rpc })
    }

    /// `ServerAlive` (opnum 3): no parameters, returns an HRESULT. A liveness/ACL probe of the
    /// DCOM subsystem and a proof that the ORPC transport binds and calls correctly.
    pub async fn server_alive(&mut self) -> Result<i32> {
        let resp = self.rpc.call(3, &[]).await?;
        let hr = resp
            .get(0..4)
            .map(|b| i32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0);
        if hr != 0 {
            return Err(RpcError::Fault(hr as u32));
        }
        Ok(hr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orpc_this_layout() {
        let cid = [0xABu8; 16];
        let b = orpc_this(&cid);
        assert_eq!(b.len(), 32, "ORPCTHIS is 32 bytes");
        assert_eq!(&b[0..2], &5u16.to_le_bytes()); // COMVERSION major
        assert_eq!(&b[2..4], &7u16.to_le_bytes()); // COMVERSION minor
        assert_eq!(&b[4..8], &[1, 0, 0, 0]); // flags
        assert_eq!(&b[8..12], &[0, 0, 0, 0]); // reserved
        assert_eq!(&b[12..28], &cid); // causality id
        assert_eq!(&b[28..32], &[0, 0, 0, 0]); // null extensions ptr
    }

    // Live: proves the DCOM OXID-resolver binds + answers on the lab DC.
    //   ADH_DC=192.168.10.1 cargo test -p dcerpc --lib dcom -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "live DC"]
    async fn server_alive_live() {
        let Ok(dc) = std::env::var("ADH_DC") else {
            return;
        };
        let mut oe = ObjectExporter::connect(&dc)
            .await
            .expect("connect IObjectExporter");
        let hr = oe.server_alive().await.expect("ServerAlive");
        assert_eq!(hr, 0, "ServerAlive HRESULT should be S_OK");
    }
}
