# dcerpc

[![Crates.io](https://img.shields.io/crates/v/dcerpc.svg)](https://crates.io/crates/dcerpc)
[![Docs.rs](https://docs.rs/dcerpc/badge.svg)](https://docs.rs/dcerpc)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A pure-Rust, **no-FFI** DCE/RPC (MS-RPCE) stack — hand-rolled NDR marshaling, connection-oriented
PDUs, **NTLMSSP sign+seal** for packet privacy, and both TCP (`ncacn_ip_tcp`) and SMB named-pipe
(`ncacn_np`) transports. On top of the transport: the endpoint mapper (EPM) plus clients for a
dozen Windows MS-RPC interfaces (SAMR, LSAT, DRSUAPI, SVCCTL, TSCH, EFSR, RPRN, ICPR, SRVSVC,
FSRVP, DFSNM, RRP, Netlogon, DCOM/WMI).

Together with [`smb2-client`](https://crates.io/crates/smb2-client),
[`ntlmssp`](https://crates.io/crates/ntlmssp) and [`ms-ndr`](https://crates.io/crates/ms-ndr),
this is the "impacket for Rust" that didn't otherwise exist — usable from Linux/macOS against a
Windows domain, static-linkable, one binary.

## Status

**`0.2.2`** — actively developed. Part of the
[icedracon Rust offensive AD ecosystem](https://github.com/icedracon) and dogfooded by
[`adhammer`](https://crates.io/crates/adhammer).

### What's new in 0.2.2

- **Fire-and-forget `CloseKey`** — the MS-RRP `BaseRegCloseKey` opnum now buffers into a
  `VecDeque<Hkey>` and flushes as an SMB `WRITE` (instead of the round-trip `TRANSCEIVE`) at
  `MAX_DEFERRED = 96` or on the next explicit close. Removes a full RPC round-trip per registry
  handle we open — noticeable on ADCS ESC-registry sweeps that walk dozens of subkeys.
- **`ms-nrpc` wire (defensive re-exports)** — the pure byte-level Netlogon primitives
  (`aes_cfb8_encrypt`, `session_key`, `encode_req_challenge`, `encode_authenticate3`, plus the
  shared constants) are now `pub use` re-exports of [`ms-nrpc`](https://crates.io/crates/ms-nrpc)
  so downstream detection code shares one implementation. The **destructive** Zerologon writers
  (`exploit_set_empty_password`, `restore_password`, `restore_password_cleartext`) intentionally
  stay inline — they carry a `dcerpc::Syntax` / `RpcTcp` in their signatures and cross-crate
  re-export would make the two `dcerpc` versions in the resolve graph collide at rustc's type
  checker.

## What it does

`dcerpc` is a layered stack you can either drive at the interface level (the high-level clients)
or hand-roll against directly (the PDU / NDR / transport primitives, useful when the interface
you need isn't shipped).

```text
[ ncacn_ip_tcp  |  ncacn_np (SMB named pipe via smb2-client) ]       transport
[ bind · alter-context · request · response · fault ]                 pdu
[ NDR (via ms-ndr): alignment · c-v arrays · unique ptrs · UTF-16 ]   ndr
[ NTLMSSP sign+seal — auth_level PKT_PRIVACY (via ntlmssp) ]          seal
[ interface clients: SAMR · LSAT · DRSUAPI · SVCCTL · … ]             api
```

## Usage

### SAMR — enumerate domain users over an authenticated SMB pipe

```rust
use dcerpc::samr::SamrClient;
use smb2_client::SmbClient;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let mut smb = SmbClient::connect("dc.corp.local:445").await?;
smb.login("dc.corp.local", "CORP", "alice", "P@ssw0rd").await?;
smb.tree_connect(r"\\dc.corp.local\IPC$").await?;
let pipe = smb.open_pipe("samr").await?;
let mut samr = SamrClient::bind(&mut smb, pipe).await?;
for (rid, name) in samr.enumerate_all_users(r"\\dc.corp.local").await? {
    println!("{rid}\t{name}");
}
# Ok(()) }
```

### Zerologon safe-detect (CVE-2020-1472, non-destructive)

```rust
use dcerpc::netlogon::{detect_zerologon, Zerologon};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
match detect_zerologon("10.10.10.22", "DC01", 2000).await? {
    Zerologon::Vulnerable => println!("VULNERABLE (safe-detect only, no reset)"),
    Zerologon::Patched   => println!("patched"),
    Zerologon::Unreachable => println!("no netlogon on the wire"),
}
# Ok(()) }
```

`detect_zerologon` sends `NetrServerReqChallenge` + `NetrServerAuthenticate3` with the all-zero
authenticator described in Secura's original PoC and reads back the `ret_status` — it never
touches `NetrServerPasswordSet2`, so the DC's machine account is never zeroed. For the
destructive path (adhammer's `attack zerologon` after user confirmation), see
`exploit_set_empty_password` + the two `restore_password*` variants in the same module.

## Interfaces shipped

| Module | Interface (UUID) | Notable use |
|--------|------------------|-------------|
| `samr`     | `12345778-1234-abcd-ef00-0123456789ac` | SAMR — enumerate domain/users/groups/admins |
| `lsat`     | `12345778-1234-abcd-ef00-0123456789ab` | LSAT — name ↔ SID lookup, LookupNames/LookupSids |
| `drsuapi`  | `e3514235-4b06-11d1-ab04-00c04fc2dcd2` | DCSync (`DRSGetNCChanges`) — **deprecated 0.2.1**, moved to [`ms-drsr`](https://crates.io/crates/ms-drsr); removal in `0.4.0` |
| `svcctl`   | `367abb81-9844-35f1-ad32-98f038001003` | Service create/start/stop — the psexec-style RCE path |
| `tsch`     | `86d35949-83c9-4044-b424-db363231fd0c` | Task Scheduler XML — `atexec`-style RCE |
| `efsr`     | `c681d488-d850-11d0-8c52-00c04fd90f7e` | EFSR — PetitPotam coercion (`EfsRpcOpenFileRaw`) |
| `rprn`     | `12345678-1234-abcd-ef00-0123456789ab` | Print System (SpoolSs) — PrinterBug coercion |
| `icpr`     | `91ae6020-9e3c-11cf-8d7c-00aa00c091be` | AD CS enrollment (`CertServerRequest`) — ESC1 |
| `srvsvc`   | `4b324fc8-1670-01d3-1278-5a47bf6ee188` | Session enum, share enum |
| `fsrvp`    | `a8e0653c-2744-4389-a61d-7373df8b2292` | File Server Remote VSS Protocol — snapshot creation |
| `dfsnm`    | `4fc742e0-4a10-11cf-8273-00aa004ae673` | DFS namespace management |
| `rrp`      | `338cd001-2244-31f1-aaaa-900038001003` | Windows Remote Registry — ADCS ESC6/7/10/11/16 detection |
| `netlogon` | `12345678-1234-abcd-ef00-01234567cffb` | Zerologon safe-detect + destructive writers |
| `dcom` / `dcom_wmi` | `4d9f4ab8-7d1c-11cf-861e-0020af6e7c57` (OXID) + WMI | DCOM activation → OXID resolve → `IWbemServices::ExecMethod Win32_Process.Create` |

Every module carries an `opnum` submodule with the canonical opcodes, an `encode_*`/`decode_*`
pair per opnum you can drive yourself, and (where async makes sense) a higher-level `*Client`
that owns the pipe/transport.

## What works / what does not (this version)

- ✅ Full RPC bind with `PKT_PRIVACY` (NTLMSSP sign+seal) over both TCP and SMB named pipes.
- ✅ EPM `ept_map` to resolve dynamic ports.
- ✅ Interfaces above are byte-tested against protocol specs and live-validated against
  fully-patched Windows Server 2022 / 2025 lab DCs.
- ✅ DCOM/WMI activation → `Win32_Process.Create` with pass-the-hash support.
- ⚠ `drsuapi` module is a `#[deprecated]` re-export shim — new code should depend on
  [`ms-drsr`](https://crates.io/crates/ms-drsr) directly. Will be removed in `0.4.0`.
- ⚠ Only `PKT_PRIVACY` (sign+seal) is exercised. `PKT_INTEGRITY` (sign-only) is not on the
  hot path for the interfaces shipped, so it's not wired.
- ⚠ SASL/SPNEGO with Kerberos is out of scope — this crate uses NTLMSSP; if you already have
  a TGS the KRB path lives in [`adhammer-kerberos`](https://github.com/icedracon/adhammer).

## Related icedracon crates

- [`ms-ndr`](https://crates.io/crates/ms-ndr) — the NDR transfer syntax primitives this crate
  builds on (aligned primitives, conformant/varying arrays, referent pointers, UTF-16LE
  c-v strings).
- [`ntlmssp`](https://crates.io/crates/ntlmssp) — NTLMv2 + MIC + key-exch + RC4 sign+seal used
  for the RPC auth layer.
- [`smb2-client`](https://crates.io/crates/smb2-client) — async SMB2 client that carries the
  `ncacn_np` named-pipe transport (with `TCP_NODELAY` — ~12× faster on small-request paths).
- [`ms-nrpc`](https://crates.io/crates/ms-nrpc) — defensive Netlogon byte-level primitives now
  re-exported by `dcerpc::netlogon`.
- [`ms-drsr`](https://crates.io/crates/ms-drsr) — the extracted DRSUAPI/DCSync module.
- [`ms-icpr`](https://crates.io/crates/ms-icpr) — the extracted ICPR (AD CS) enrollment client
  with an offline CSR builder.
- [`windows-sddl`](https://crates.io/crates/windows-sddl) — `Sid`/`Guid` types + security-
  descriptor parser used by SAMR/LSAT decoders.
- [`adhammer`](https://crates.io/crates/adhammer) — the AD security-assessment toolkit that
  drives this stack end-to-end.

## License

MIT © 2026 [zevs](https://github.com/icedracon). Extracted from
[ADhammer](https://github.com/icedracon/adhammer).

Authorized-testing / research / education use only.
