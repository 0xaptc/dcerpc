//! MS-RRP — the Windows Remote Registry protocol over `\PIPE\winreg`. Read remote registry
//! values, which is what several AD CS ESC detections need but LDAP can't see:
//!
//! - **ESC6**  — CA `EditFlags` & `EDITF_ATTRIBUTESUBJECTALTNAME2` (0x00040000)
//! - **ESC11** — CA `InterfaceFlags` & `IF_ENFORCEENCRYPTICERTREQUEST` (0x00000200) *not* set
//! - **ESC16** — CA `DisableExtensionList` contains the szOID_NTDS_CA_SECURITY_EXT
//! - **ESC7**  — CA `Security` (a SECURITY_DESCRIPTOR; ManageCA/ManageCertificates ACEs)
//! - **ESC10** — DC `Kdc\StrongCertificateBindingEnforcement` / Schannel `CertificateMappingMethods`
//!
//! Requires the target's Remote Registry service to be reachable on the `\winreg` pipe. Rides the
//! same authenticated SMB transport as the SAMR/SVCCTL clients.
//!
//! Status: client + marshaling; `BaseRegQueryValue`'s size dance is validated live against a lab
//! (needs Remote Registry running).

use crate::ndr::{NdrDecoder, NdrEncoder};
use crate::transport::SmbPipe;
use crate::{required_tail_u32, Result, RpcError, Syntax};
use smb2_client::SmbClient;

/// The Windows Remote Registry interface (winreg, v1.0).
pub fn winreg_syntax() -> Syntax {
    Syntax::new("338cd001-2244-31f1-aaaa-900038001003", 1, 0)
}

pub mod opnum {
    pub const OPEN_LOCAL_MACHINE: u16 = 2; // OpenHKLM
    pub const OPEN_USERS: u16 = 4; // OpenHKU
    pub const BASE_REG_CLOSE_KEY: u16 = 5;
    pub const BASE_REG_ENUM_KEY: u16 = 9;
    pub const BASE_REG_OPEN_KEY: u16 = 15;
    pub const BASE_REG_QUERY_INFO_KEY: u16 = 16;
    pub const BASE_REG_QUERY_VALUE: u16 = 17;
}

/// REGSAM for read-only value access (STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | ENUM | NOTIFY).
const KEY_READ: u32 = 0x0002_0019;
/// Read buffer handed to BaseRegQueryValue (CA `Security` SDs are the largest values we read).
const QUERY_BUF: u32 = 0x0002_0000; // 128 KiB
/// Safety cap on the HKU subkey enumeration loop.
const MAX_SUBKEYS: u32 = 100_000;

/// A 20-byte RPC_HKEY policy handle (attributes u32 + 16-byte context uuid).
#[derive(Clone, Copy, Debug, Default)]
pub struct Hkey(pub [u8; 20]);

impl Hkey {
    fn decode(d: &mut NdrDecoder) -> Result<Self> {
        let attrs = d.u32()?;
        let uuid = d.uuid()?;
        let mut h = [0u8; 20];
        h[..4].copy_from_slice(&attrs.to_le_bytes());
        h[4..].copy_from_slice(&uuid);
        Ok(Hkey(h))
    }
    fn encode(&self, e: &mut NdrEncoder) {
        e.bytes(&self.0);
    }
    fn is_null(&self) -> bool {
        self.0 == [0u8; 20]
    }
}

/// A registry value's type + raw data.
#[derive(Clone, Debug)]
pub struct RegValue {
    pub ty: u32, // REG_DWORD=4, REG_BINARY=3, REG_SZ=1, REG_MULTI_SZ=7, …
    pub data: Vec<u8>,
}

impl RegValue {
    /// Interpret a REG_DWORD (little-endian) — the common case for CA/DC flag values.
    pub fn as_dword(&self) -> Option<u32> {
        self.data
            .get(0..4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
    /// Interpret REG_SZ / REG_MULTI_SZ as UTF-16LE text (NULs → newlines for MULTI_SZ).
    pub fn as_string(&self) -> String {
        let units: Vec<u16> = self
            .data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
            .replace('\0', "\n")
            .trim()
            .to_string()
    }
}

/// A user profile currently loaded on the target (a HKU subkey).
/// Returned by [`RegistryClient::logged_on_sids`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrySession {
    /// SID of the logged-on principal (e.g. `S-1-5-21-…-1103`).
    pub sid: String,
}

/// Encode an `RRP_UNICODE_STRING` (RPC_UNICODE_STRING): Length + MaximumLength (bytes, NUL
/// included) + a non-null Buffer referent, then the deferred conformant-varying wchar array.
fn encode_ustr(e: &mut NdrEncoder, s: &str) {
    let mut units: Vec<u16> = s.encode_utf16().collect();
    units.push(0); // trailing NUL — RRP counts it in Length
    let n = units.len() as u32;
    let bytes = (n * 2) as u16;
    e.u16(bytes); // Length
    e.u16(bytes); // MaximumLength
    e.referent(); // Buffer (non-null)
    e.u32(n); // max_count
    e.u32(0); // offset
    e.u32(n); // actual_count
    for u in units {
        e.u16(u);
    }
    e.align(4);
}

fn encode_open_local_machine() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.null_ptr(); // ServerName [in, unique] → NULL (this host)
    e.u32(KEY_READ); // samDesired
    e.into_bytes()
}

fn encode_open_users() -> Vec<u8> {
    encode_open_local_machine() // identical wire format, different opnum
}

fn encode_open_key(hkey: &Hkey, subkey: &str) -> Vec<u8> {
    encode_open_key_opts(hkey, subkey, 0)
}

fn encode_open_key_opts(hkey: &Hkey, subkey: &str, dw_options: u32) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    hkey.encode(&mut e);
    encode_ustr(&mut e, subkey);
    e.u32(dw_options); // dwOptions; REG_OPTION_BACKUP_RESTORE=4 uses SeBackupPrivilege on SAM/SECURITY
    e.u32(KEY_READ); // samDesired
    e.into_bytes()
}

fn encode_query_value(hkey: &Hkey, value: &str) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    hkey.encode(&mut e);
    encode_ustr(&mut e, value);
    // lpType [in,out,unique] → referent + DWORD(0)
    e.referent();
    e.u32(0);
    // lpData [in,out,unique,size_is(*lpcbData)] → referent + conformant/varying header, no bytes in
    e.referent();
    e.u32(QUERY_BUF); // max_count (conformance = buffer we offer)
    e.u32(0); // offset
    e.u32(0); // actual_count (in-value: empty)
              // lpcbData [in,out,unique] → referent + DWORD(buffer size)
    e.referent();
    e.u32(QUERY_BUF);
    // lpcbLen [in,out,unique] → referent + DWORD(0)
    e.referent();
    e.u32(0);
    e.into_bytes()
}

fn encode_close(hkey: &Hkey) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    hkey.encode(&mut e);
    e.into_bytes()
}

/// Parse the BaseRegQueryValue reply: [out] lpType, lpData (conformant-varying byte array),
/// lpcbData, lpcbLen, then the Win32 return. Returns the value's type + bytes.
#[doc(hidden)]
pub fn decode_query_value(stub: &[u8]) -> Result<RegValue> {
    let ret = required_tail_u32(stub, "BaseRegQueryValue")?;
    if ret != 0 {
        return Err(RpcError::Protocol(format!(
            "BaseRegQueryValue failed (win32 {ret})"
        )));
    }
    let mut d = NdrDecoder::new(stub);
    // lpType (unique)
    let mut ty = 0u32;
    if d.u32()? != 0 {
        ty = d.u32()?;
    }
    // lpData (unique) → conformant-varying byte array
    let mut data = Vec::new();
    if d.u32()? != 0 {
        let max = d.u32()?;
        let off = d.u32()?;
        let actual = d.u32()? as usize;
        if off > max || (actual as u32) > max - off {
            return Err(RpcError::Protocol(format!(
                "BaseRegQueryValue invalid varying array max={max}, offset={off}, actual={actual}"
            )));
        }
        data = d.read_bytes(actual)?.to_vec();
        d.align(4);
    }
    let data_len = if d.u32()? != 0 { Some(d.u32()?) } else { None };
    let total_len = if d.u32()? != 0 { Some(d.u32()?) } else { None };
    let decoded_ret = d.u32()?;
    if decoded_ret != ret {
        return Err(RpcError::Protocol(
            "BaseRegQueryValue status position is inconsistent".into(),
        ));
    }
    if let Some(data_len) = data_len {
        if data.len() > data_len as usize {
            return Err(RpcError::Protocol(format!(
                "BaseRegQueryValue returned {} bytes but lpcbData={data_len}",
                data.len()
            )));
        }
    }
    if let Some(total_len) = total_len {
        if let Some(data_len) = data_len {
            if total_len < data_len {
                return Err(RpcError::Protocol(format!(
                    "BaseRegQueryValue lpcbLen={total_len} is smaller than lpcbData={data_len}"
                )));
            }
        }
    }
    Ok(RegValue { ty, data })
}

/// High-level RRP client bound over an SMB `\PIPE\winreg`.
///
/// v1.3.6 fire-and-forget close: `close_handle_no_wait` touches wire ZERO times; server-side
/// cleanup happens via MS-RPCE §3.3.3.5.1 Context Handle Rundown when the pipe closes.
/// Safety valve at MAX_DEFERRED flushes the OLDEST handle synchronously via TRANSCEIVE.
pub struct RegistryClient<'a> {
    pipe: SmbPipe<'a>,
    deferred: std::collections::VecDeque<Hkey>,
}

const MAX_DEFERRED: usize = 96;

impl<'a> RegistryClient<'a> {
    /// Open `\winreg` on an already-authenticated SMB session and bind winreg (sign+seal).
    pub async fn connect(
        client: &'a mut SmbClient,
        domain: &str,
        user: &str,
        password: &str,
        host: &str,
    ) -> Result<RegistryClient<'a>> {
        let file_id = client
            .open_pipe("winreg")
            .await
            .map_err(|e| RpcError::Protocol(format!("open \\winreg: {e}")))?;
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind_sealed(winreg_syntax(), domain, user, password, host)
            .await?;
        Ok(RegistryClient {
            pipe,
            deferred: std::collections::VecDeque::new(),
        })
    }

    /// Like [`Self::connect`] but authenticate with a raw NT hash instead of a
    /// plaintext password — pass-the-hash at the RPC sign+seal (bind_sealed) layer.
    ///
    /// Use when the SMB session was opened with `SmbClient::login_hash`:
    /// `connect()` would send the NT hash of `""` in the RPC BIND, which the
    /// server rejects with `RPC fault 0x00000005` (nca_s_fault_access_denied).
    pub async fn connect_hash(
        client: &'a mut SmbClient,
        domain: &str,
        user: &str,
        nt_hash: &[u8; 16],
        host: &str,
    ) -> Result<RegistryClient<'a>> {
        let file_id = client
            .open_pipe("winreg")
            .await
            .map_err(|e| RpcError::Protocol(format!("open \\winreg: {e}")))?;
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind_sealed_hash(winreg_syntax(), domain, user, nt_hash, host)
            .await?;
        Ok(RegistryClient {
            pipe,
            deferred: std::collections::VecDeque::new(),
        })
    }

    async fn after_open(&mut self, opened: &Hkey) -> Result<()> {
        self.deferred.push_back(*opened);
        if self.deferred.len() > MAX_DEFERRED {
            if let Some(old) = self.deferred.pop_front() {
                let _ = self
                    .pipe
                    .call_sealed(opnum::BASE_REG_CLOSE_KEY, &encode_close(&old))
                    .await;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn deferred_len(&self) -> usize {
        self.deferred.len()
    }

    /// Test-only accessor for use from adhammer's integration test binary.
    #[doc(hidden)]
    pub fn __deferred_len_debug(&self) -> usize {
        self.deferred.len()
    }

    async fn open_hklm(&mut self) -> Result<Hkey> {
        let resp = self
            .pipe
            .call_sealed(opnum::OPEN_LOCAL_MACHINE, &encode_open_local_machine())
            .await?;
        let mut d = NdrDecoder::new(&resp);
        let h = Hkey::decode(&mut d)?;
        let ret = d.u32().unwrap_or(u32::MAX);
        if ret != 0 || h.is_null() {
            return Err(RpcError::Protocol(format!(
                "OpenLocalMachine failed ({ret})"
            )));
        }
        self.after_open(&h).await?;
        Ok(h)
    }

    async fn open_hku(&mut self) -> Result<Hkey> {
        let resp = self
            .pipe
            .call_sealed(opnum::OPEN_USERS, &encode_open_users())
            .await?;
        let mut d = NdrDecoder::new(&resp);
        let h = Hkey::decode(&mut d)?;
        let ret = d.u32().unwrap_or(u32::MAX);
        if ret != 0 || h.is_null() {
            return Err(RpcError::Protocol(format!("OpenUsers failed ({ret})")));
        }
        self.after_open(&h).await?;
        Ok(h)
    }

    async fn open_key(&mut self, parent: &Hkey, subkey: &str) -> Result<Hkey> {
        let resp = self
            .pipe
            .call_sealed(opnum::BASE_REG_OPEN_KEY, &encode_open_key(parent, subkey))
            .await?;
        let mut d = NdrDecoder::new(&resp);
        let h = Hkey::decode(&mut d)?;
        let ret = d.u32().unwrap_or(u32::MAX);
        if ret != 0 || h.is_null() {
            return Err(RpcError::Protocol(format!(
                "BaseRegOpenKey('{subkey}') failed ({ret})"
            )));
        }
        self.after_open(&h).await?;
        Ok(h)
    }

    async fn query_value(&mut self, key: &Hkey, value: &str) -> Result<RegValue> {
        let resp = self
            .pipe
            .call_sealed(opnum::BASE_REG_QUERY_VALUE, &encode_query_value(key, value))
            .await?;
        decode_query_value(&resp)
    }

    async fn close(&mut self, key: &Hkey) {
        let _ = self
            .pipe
            .call_sealed(opnum::BASE_REG_CLOSE_KEY, &encode_close(key))
            .await;
    }

    /// Open `HKLM\<subkey>`, read `<value>`, close — the one-shot most ESC checks need.
    pub async fn read_value(&mut self, subkey: &str, value: &str) -> Result<RegValue> {
        let hklm = self.open_hklm().await?;
        let key = self.open_key(&hklm, subkey).await;
        let key = match key {
            Ok(k) => k,
            Err(e) => {
                self.close(&hklm).await;
                return Err(e);
            }
        };
        let v = self.query_value(&key, value).await;
        self.close(&key).await;
        self.close(&hklm).await;
        v
    }

    /// Open `HKLM` as a reusable handle — for multi-key flows (secretsdump-via-RRP) that
    /// don't want to reopen HKLM on every read.
    pub async fn hklm(&mut self) -> Result<Hkey> {
        self.open_hklm().await
    }

    /// Open `HKEY_USERS` as a reusable handle — for HKU enumeration flows.
    /// Mirrors [`hklm`](Self::hklm); the handle is deferred-closed on drop.
    pub async fn hku(&mut self) -> Result<Hkey> {
        self.open_hku().await
    }

    /// Enumerate `HKEY_USERS` subkeys and return the SIDs of principals with
    /// a logon context on the host. Each loaded user profile hive appears as a
    /// subkey named by the user's SID; `_Classes` companions are excluded.
    ///
    /// Unlike SRVSVC/WKSSVC this often works **without local admin** — Everyone
    /// has Read on HKU and subkey *names* are enumerable — but the target's
    /// Remote Registry service must be running.
    pub async fn logged_on_sids(&mut self) -> Result<Vec<RegistrySession>> {
        let hku = self.open_hku().await?;
        let mut out = Vec::new();
        for idx in 0..MAX_SUBKEYS {
            match self.enum_key(&hku, idx).await? {
                None => break,
                Some(name) if name.starts_with("S-1-5-21") && !name.ends_with("_Classes") => {
                    out.push(RegistrySession { sid: name });
                }
                _ => {}
            }
        }
        self.close_handle_no_wait(&hku).await;
        Ok(out)
    }

    /// Open a subkey under `parent`. Publicly exposed for callers that need to chain
    /// key opens (e.g. enumerate SAM users under a pre-opened `SAM\SAM\Domains\Account\Users`).
    pub async fn open(&mut self, parent: &Hkey, subkey: &str) -> Result<Hkey> {
        self.open_key(parent, subkey).await
    }

    /// Open a subkey with `REG_OPTION_BACKUP_RESTORE` (dwOptions=4) — the flag that tells
    /// the remote registry to honor `SeBackupPrivilege` on protected hives (`SAM`, `SECURITY`).
    /// A DA-level session's token has SeBackupPrivilege granted; this flag turns "denied"
    /// on `HKLM\SAM\…` into a successful read — the standard SeBackupPrivilege path.
    pub async fn open_backup(&mut self, parent: &Hkey, subkey: &str) -> Result<Hkey> {
        let resp = self
            .pipe
            .call_sealed(
                opnum::BASE_REG_OPEN_KEY,
                &encode_open_key_opts(parent, subkey, 4),
            )
            .await?;
        let mut d = NdrDecoder::new(&resp);
        let h = Hkey::decode(&mut d)?;
        let ret = d.u32().unwrap_or(u32::MAX);
        if ret != 0 || h.is_null() {
            return Err(RpcError::Protocol(format!(
                "BaseRegOpenKey('{subkey}', BACKUP_RESTORE) failed ({ret})"
            )));
        }
        self.after_open(&h).await?;
        Ok(h)
    }

    /// Read a value under an already-open key. Publicly exposed for multi-value flows.
    pub async fn query(&mut self, key: &Hkey, value: &str) -> Result<RegValue> {
        self.query_value(key, value).await
    }

    /// Close a handle when done. Publicly exposed.
    pub async fn close_handle(&mut self, key: &Hkey) {
        self.close(key).await;
    }

    /// Fire-and-forget close — **touches the wire zero times**. Marks the handle as
    /// deferred-closable; MS-RPCE §3.3.3.5.1 Context Handle Rundown invokes
    /// `BaseRegCloseKey` for every open handle when the `\PIPE\winreg` pipe closes at
    /// SMB session teardown. Saves one full sealed RPC round-trip per handle.
    ///
    /// If the caller opens more than `MAX_DEFERRED` handles without triggering teardown,
    /// the safety-valve in `after_open` synchronously closes the OLDEST deferred handle.
    ///
    /// **v1.3.4 regression note:** an earlier attempt did SMB WRITE (fire-and-forget on the
    /// sealed PDU). MS-CIFS §3.3.4.11 message-mode pipe semantics broke that: the server
    /// queued the CloseKey response as a discrete message, the next TRANSCEIVE returned
    /// that stale reply, and the sealed transport's sequence counter desynced → pipe was
    /// killed with STATUS_PIPE_CLOSING. Zero-wire is the only correct path.
    ///
    /// **Client-side note:** the server-side `Hkey` stays valid until pipe teardown, so a
    /// buggy caller that "closes" a handle then reuses it will still succeed. This masks
    /// caller bugs that would have been caught by real closes. For strict "close-now"
    /// semantics, use [`close_handle`](Self::close_handle).
    pub async fn close_handle_no_wait(&mut self, key: &Hkey) {
        if let Some(pos) = self.deferred.iter().position(|h| h.0 == key.0) {
            self.deferred.remove(pos);
        }
        // No wire I/O — pipe teardown will run BaseRegCloseKey via RPC rundown.
    }

    /// `BaseRegQueryInfoKey` — return the key's *class name* (the field the SAM bootkey lives
    /// in: 8 hex chars each in the class of `HKLM\SYSTEM\…\Lsa\{JD,Skew1,GBG,Data}`). Other
    /// fields the opnum returns are ignored — the SYSTEM-only bootkey extraction path also
    /// uses this exact primitive.
    pub async fn query_info_class(&mut self, key: &Hkey) -> Result<String> {
        let resp = self
            .pipe
            .call_sealed(opnum::BASE_REG_QUERY_INFO_KEY, &encode_query_info_key(key))
            .await?;
        decode_query_info_class(&resp)
    }

    /// `BaseRegEnumKey` — return the `dwIndex`-th subkey name of `key`, or `Ok(None)` once the
    /// enumerator runs off the end (`STATUS_NO_MORE_ITEMS = 259 = 0x103`). For SAM user
    /// enumeration under `SAM\SAM\Domains\Account\Users`.
    pub async fn enum_key(&mut self, key: &Hkey, dw_index: u32) -> Result<Option<String>> {
        let resp = self
            .pipe
            .call_sealed(opnum::BASE_REG_ENUM_KEY, &encode_enum_key(key, dw_index))
            .await?;
        decode_enum_key(&resp)
    }
}

// ─── QueryInfoKey / EnumKey wire helpers ──────────────────────────────────────────────────

/// Encode `BaseRegQueryInfoKey(hKey, lpClassIn={empty, max=1024})`. The `lpClassIn` is a
/// hint of how big a class buffer we can accept; 1024 is well above the 8-char classes we
/// actually read (bootkey source).
fn encode_query_info_key(key: &Hkey) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    key.encode(&mut e);
    // lpClassIn: RRP_UNICODE_STRING with Length=0, MaximumLength=1024 (bytes), Buffer referent.
    e.u16(0); // Length
    e.u16(1024); // MaximumLength
    e.referent(); // Buffer
    e.u32(512); // max_count (wchars = 1024 bytes / 2)
    e.u32(0); // offset
    e.u32(0); // actual_count (empty in-value)
    e.into_bytes()
}

/// Decode `BaseRegQueryInfoKey`: consume up to lpClassOut and return its UTF-16LE text.
/// The rest of the reply (subkey/value counts, last-write time, HRESULT) is discarded — we
/// only care about the class name here.
#[doc(hidden)]
pub fn decode_query_info_class(stub: &[u8]) -> Result<String> {
    let ret = required_tail_u32(stub, "BaseRegQueryInfoKey")?;
    if ret != 0 {
        return Err(RpcError::Protocol(format!(
            "BaseRegQueryInfoKey failed (win32 {ret})"
        )));
    }
    let mut d = NdrDecoder::new(stub);
    // lpClassOut: RRP_UNICODE_STRING { Length, MaximumLength, Buffer[unique] } then deferred
    // WSTR buffer if referent != 0. Length is the used bytes (NUL included).
    let length = d.u16()?;
    let _maximum_length = d.u16()?;
    let referent = d.u32()?;
    if referent == 0 || length == 0 {
        return Ok(String::new());
    }
    let _max = d.u32()?;
    let _off = d.u32()?;
    let actual = d.u32()? as usize;
    // Bounded-alloc preflight: `actual` is attacker-controlled u32. Each unit is 2 wire
    // bytes, so cap the reservation against remaining stub before `Vec::with_capacity`.
    if actual
        .checked_mul(2)
        .map_or(true, |need| need > d.remaining())
    {
        return Err(RpcError::Protocol(format!(
            "BaseRegQueryInfoKey: lpClassOut actual={actual} exceeds remaining stub"
        )));
    }
    let mut units = Vec::with_capacity(actual);
    for _ in 0..actual {
        units.push(d.u16()?);
    }
    // Strip trailing NUL(s).
    while units.last() == Some(&0) {
        units.pop();
    }
    Ok(String::from_utf16_lossy(&units))
}

/// Encode `BaseRegEnumKey(hKey, dwIndex, lpNameIn={empty,max=1024}, lpClassIn=64-spaces)`.
///
/// Matches the MS-RRP `BaseRegEnumKey` IDL byte-for-byte: `lpNameIn` is an EMPTY RRP_UNICODE_STRING
/// with MaximumLength=1024 (so the server can write up to 512 wchars into its buffer), and
/// `lpClassIn` is `' ' * 64` — the observed accepted placeholder. Sending an "empty pointer" for
/// `lpClassIn` gets `nca_s_fault_ndr` on Server 2016+; a real 64-char string is what the
/// server's stub expects.
fn encode_enum_key(key: &Hkey, dw_index: u32) -> Vec<u8> {
    const CAP_WCHARS: u32 = 512;
    let mut e = NdrEncoder::new();
    key.encode(&mut e);
    e.u32(dw_index);
    // lpNameIn — INLINE (not pointer): Length=0, MaximumLength=1024, Buffer referent,
    // deferred conformant-varying with actual_count=0 (no bytes follow).
    e.u16(0);
    e.u16((CAP_WCHARS * 2) as u16);
    e.referent();
    e.u32(CAP_WCHARS); // max_count
    e.u32(0); // offset
    e.u32(0); // actual_count = 0 (empty)
              // lpClassIn [in,unique] → non-null pointer to RRP_UNICODE_STRING("                                                                ")
              // (' ' * 64 = 64 wchars).
    e.referent(); // top-level unique pointer referent
    const SPACES: u32 = 64;
    // deferred pointee: RRP_UNICODE_STRING
    e.u16((SPACES * 2) as u16); // Length (bytes)
    e.u16((SPACES * 2 + 2) as u16); // MaximumLength (bytes, includes trailing NUL slot)
    e.referent(); // Buffer
    e.u32(SPACES + 1); // max_count = 65 wchars (spaces + NUL)
    e.u32(0);
    e.u32(SPACES); // actual_count = 64 (the 64 spaces sent)
    for _ in 0..SPACES {
        e.u16(0x20); // ' '
    }
    // lpftLastWriteTime [in,out,unique] → NULL
    e.null_ptr();
    e.into_bytes()
}

/// Decode `BaseRegEnumKey`: pull out the returned subkey name.
/// Returns `Ok(None)` if the server signalled `STATUS_NO_MORE_ITEMS` (0x00000103) at the
/// tail — the normal end-of-enumeration marker.
#[doc(hidden)]
pub fn decode_enum_key(stub: &[u8]) -> Result<Option<String>> {
    let ret = required_tail_u32(stub, "BaseRegEnumKey")?;
    if ret == 0x0000_0103 {
        // NO_MORE_ITEMS — normal end of enumeration.
        return Ok(None);
    }
    if ret == 0x0000_00EA {
        return Err(RpcError::Protocol(
            "BaseRegEnumKey returned ERROR_MORE_DATA; supplied name buffer was too small".into(),
        ));
    }
    if ret != 0 {
        return Err(RpcError::Protocol(format!(
            "BaseRegEnumKey failed (win32 {ret})"
        )));
    }
    let mut d = NdrDecoder::new(stub);
    // lpNameOut RRP_UNICODE_STRING { Length, MaximumLength, Buffer[unique] }
    let length = d.u16()?;
    let _max_len = d.u16()?;
    let referent = d.u32()?;
    if referent == 0 || length == 0 {
        return Ok(Some(String::new()));
    }
    let _max = d.u32()?;
    let _off = d.u32()?;
    let actual = d.u32()? as usize;
    // Bounded-alloc preflight: `actual` is attacker-controlled u32. Each unit is 2 wire
    // bytes, so cap the reservation against remaining stub before `Vec::with_capacity`.
    if actual
        .checked_mul(2)
        .map_or(true, |need| need > d.remaining())
    {
        return Err(RpcError::Protocol(format!(
            "BaseRegEnumKey: lpNameOut actual={actual} exceeds remaining stub"
        )));
    }
    let mut units = Vec::with_capacity(actual);
    for _ in 0..actual {
        units.push(d.u16()?);
    }
    while units.last() == Some(&0) {
        units.pop();
    }
    Ok(Some(String::from_utf16_lossy(&units)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le16(b: &[u8], o: usize) -> u16 {
        u16::from_le_bytes([b[o], b[o + 1]])
    }
    fn le32(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
    }

    #[test]
    fn ustr_counts_include_nul() {
        let mut e = NdrEncoder::new();
        encode_ustr(&mut e, "AB");
        let b = e.into_bytes();
        // Length/MaximumLength = (2 chars + NUL) * 2 = 6 bytes.
        assert_eq!(le16(&b, 0), 6);
        assert_eq!(le16(&b, 2), 6);
        assert_ne!(le32(&b, 4), 0); // Buffer referent non-null
        assert_eq!(le32(&b, 8), 3, "max_count = 3 (A B NUL)");
        assert_eq!(le32(&b, 12), 0, "offset");
        assert_eq!(le32(&b, 16), 3, "actual_count");
        assert_eq!(le16(&b, 20), b'A' as u16);
    }

    #[test]
    fn open_local_machine_stub() {
        let b = encode_open_local_machine();
        assert_eq!(le32(&b, 0), 0, "ServerName NULL");
        assert_eq!(le32(&b, 4), KEY_READ);
    }

    #[test]
    fn open_users_stub_matches_open_local_machine() {
        // Same wire format, different opnum — the encoding must be identical.
        assert_eq!(encode_open_users(), encode_open_local_machine());
    }

    #[test]
    fn registry_session_sid_filter() {
        // Keep this in sync with the filter in logged_on_sids().
        let keep = |s: &str| s.starts_with("S-1-5-21") && !s.ends_with("_Classes");
        assert!(keep("S-1-5-21-111-222-333-1103"));
        assert!(!keep("S-1-5-21-111-222-333-1103_Classes")); // companion hive
        assert!(!keep(".DEFAULT")); // machine default profile
        assert!(!keep("S-1-5-18")); // LOCAL SYSTEM
    }

    #[test]
    fn query_value_roundtrip_decodes_dword() {
        // Build a synthetic reply: lpType(REG_DWORD) + lpData(4-byte 0x00040000) + sizes + ret 0.
        let mut e = NdrEncoder::new();
        e.referent();
        e.u32(4); // REG_DWORD
        e.referent();
        e.u32(4); // max_count
        e.u32(0); // offset
        e.u32(4); // actual_count
        e.bytes(&0x0004_0000u32.to_le_bytes());
        e.align(4);
        e.referent();
        e.u32(4); // lpcbData
        e.referent();
        e.u32(4); // lpcbLen
        e.u32(0); // return
        let v = decode_query_value(&e.into_bytes()).unwrap();
        assert_eq!(v.ty, 4);
        assert_eq!(v.as_dword(), Some(0x0004_0000));
    }

    // Hostile server: RRP_UNICODE_STRING with a non-zero length + referent, then a
    // maliciously large `actual` in the deferred WSTR header, then a truncated body.
    // Both decode_query_info_class and decode_enum_key must return Err(Protocol)
    // instead of `Vec::<u16>::with_capacity(0xFFFF_FFFF)` → ~8 GB alloc / abort.
    fn hostile_ustr_reply(hostile_actual: u32) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&2u16.to_le_bytes()); // Length (non-zero — get past early return)
        r.extend_from_slice(&2u16.to_le_bytes()); // MaximumLength
        r.extend_from_slice(&0x2_0000u32.to_le_bytes()); // Buffer referent (non-null)
        r.extend_from_slice(&hostile_actual.to_le_bytes()); // max_count
        r.extend_from_slice(&0u32.to_le_bytes()); // offset
        r.extend_from_slice(&hostile_actual.to_le_bytes()); // actual_count
                                                            // (no body follows — server truncates here)
        r
    }

    #[test]
    fn query_info_class_actual_is_bounded_against_stub() {
        let mut stub = hostile_ustr_reply(0xFFFF_FFFF);
        stub.extend_from_slice(&0u32.to_le_bytes());
        let err = decode_query_info_class(&stub).unwrap_err();
        assert!(
            matches!(err, RpcError::Protocol(ref s) if s.contains("actual=")),
            "expected Protocol(actual …), got {err:?}"
        );
    }

    #[test]
    fn enum_key_actual_is_bounded_against_stub() {
        // decode_enum_key sniffs the last 4 bytes for the win32 return; ret==0 lets us reach
        // the parse. Append a trailing 0u32 after our hostile ustr so the tail sniff sees 0.
        let mut stub = hostile_ustr_reply(0xFFFF_FFFF);
        stub.extend_from_slice(&0u32.to_le_bytes());
        let err = decode_enum_key(&stub).unwrap_err();
        assert!(
            matches!(err, RpcError::Protocol(ref s) if s.contains("actual=")),
            "expected Protocol(actual …), got {err:?}"
        );
    }
}
