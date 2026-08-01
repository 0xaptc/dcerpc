// Live Stage-1 WMI activation probe: RemoteCreateInstance of IWbemLevel1Login against a DC.
// HRESULT 0 = the SCM accepted the activation blob (E_FAIL 0x80004005 = still refused).
//   P=... U=administrator D=TESTLAB DC=10.10.10.22 cargo run --example wmi_probe
use std::env;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("DC").unwrap_or_else(|_| "10.10.10.22".into());
    let domain = env::var("D").unwrap_or_else(|_| "TESTLAB".into());
    let user = env::var("U").unwrap_or_else(|_| "administrator".into());
    let pass = env::var("P").expect("set P=<password>");
    let clsid = "8bc3f05e-d86b-11d0-a075-00c04fb68820"; // CLSID_WbemLevel1Login
    let iid = "f309ad18-d86a-11d0-a075-00c04fb68820"; // IID_IWbemLevel1Login

    let reply =
        dcerpc::dcom_wmi::remote_create_instance_raw(&host, &domain, &user, &pass, "ADHAMMER", clsid, &[iid])
            .await?;
    let hr = dcerpc::dcom_wmi::activation_hresult(&reply);
    println!("reply_len={} HRESULT=0x{:08x}", reply.len(), hr as u32);
    if hr == 0 {
        match dcerpc::dcom_wmi::parse_stdobjref(&reply) {
            Ok(o) => println!("[+] ACTIVATION ACCEPTED — STDOBJREF oxid={:#x} oid={:#x}", o.oxid, o.oid),
            Err(e) => println!("[+] HRESULT ok but STDOBJREF parse: {e}"),
        }
    } else {
        println!("[-] activation refused (0x{:08x})", hr as u32);
    }
    Ok(())
}
