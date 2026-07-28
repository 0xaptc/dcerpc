# dcerpc

[![crates.io](https://img.shields.io/crates/v/dcerpc.svg)](https://crates.io/crates/dcerpc)
[![docs.rs](https://img.shields.io/docsrs/dcerpc)](https://docs.rs/dcerpc)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A pure-Rust, **no-FFI** DCE/RPC (MS-RPCE) stack — hand-rolled NDR marshaling, RPC PDUs,
**NTLMSSP sign+seal** for packet privacy, and both TCP (`ncacn_ip_tcp`) and SMB named-pipe
(`ncacn_np`) transports. On top of it: the endpoint mapper (EPM) and clients for common MS-RPC
interfaces (SAMR, LSAT, DRSUAPI, SVCCTL, EFSR, RPRN, ICPR/AD CS).

Together with [`smb2-client`](https://crates.io/crates/smb2-client) and
[`ntlmssp`](https://crates.io/crates/ntlmssp), this is the "impacket for Rust" that didn't
previously exist — usable from Linux/macOS against Windows.

## Features

- **NDR** encoder/decoder (alignment, conformant/varying arrays, unique/referent pointers) with
  spec-vector tests.
- RPC PDUs: bind / alter-context / request / response, with **auth level PKT_PRIVACY**
  (NTLMSSP sign+seal — the packet privacy DCs require for replication and SCM).
- Transports: TCP + SMB named pipe (via `smb2-client`), plus EPM `ept_map` to resolve dynamic
  ports.
- Interface clients: **SAMR** (enumerate domain users/groups), **LSAT** (name↔SID), **DRSUAPI**
  (DCSync — DRSBind / DRSCrackNames / DRSGetNCChanges), **SVCCTL** (service create/run — RCE),
  **EFSR/RPRN** (coercion), **ICPR** (AD CS enrollment).

## Example — SAMR user enumeration over SMB

```rust
use dcerpc::samr::SamrClient;
use smb2_client::SmbClient;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let mut smb = SmbClient::connect("dc:445").await?;
smb.login("dc", "CORP", "alice", "P@ssw0rd").await?;
smb.tree_connect(r"\\dc\IPC$").await?;
let pipe = smb.open_pipe("samr").await?;
let mut samr = SamrClient::bind(&mut smb, pipe).await?;
for (rid, name) in samr.enumerate_all_users(r"\\dc").await? {
    println!("{rid}\t{name}");
}
# Ok(()) }
```

## Status

Every parser/marshaler is unit-tested against protocol specs (NDR alignment/strings, PDU shapes,
EPM tower, SAMR/LSAT/ICPR layouts). Authorized-testing / research / education use.

## License

MIT © icedracon. Extracted from [ADhammer](https://github.com/icedracon/adhammer).
