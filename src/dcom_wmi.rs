//! WMI execution over DCOM (MS-DCOM + MS-WMI), the `wmiexec` primitive, built on the
//! [`crate::dcom`] OXID-resolver foundation. Staged:
//!
//!   Stage 1 (this module): `ISystemActivator::RemoteCreateInstance` — marshal the
//!     activation-properties blob to instantiate `CLSID_WbemLevel1Login` and request
//!     `IID_IWbemLevel1Login`, then parse the reply for the returned OXID / IPID / OID.
//!   Stage 2: resolve the OXID → dynamic endpoint, bind, `IWbemLevel1Login::NTLMLogin` → an
//!     `IWbemServices` interface pointer for `root\cimv2`.
//!   Stage 3: `IWbemServices::ExecMethod` `Win32_Process.Create` with the CIM in-params object.
//!
//! Activation properties, the CustomHeader, and each property are NDR "type serialization v1"
//! pickles (the 16-byte common+private header we already use for the PAC), wrapped in an
//! `OBJREF_CUSTOM` (MInterfacePointer). References: MS-DCOM §2.2.22 (Activation Properties),
//! §2.2.18 (OBJREF), §2.2.19 (STDOBJREF / DUALSTRINGARRAY).
//!
//! **STATUS (live against a Server 2022 DC):** the sealed NTLM bind to ISystemActivator on
//! ncacn_ip_tcp:135 and the `RemoteCreateInstance` (opnum 4) call both succeed, and the server
//! *unmarshals* the six-property activation blob cleanly (no more `nca_s_fault_ndr`). The SCM then
//! returns `E_FAIL (0x80004005)` — a semantic activation refusal with no field locality. Pinning
//! the remaining property-field discrepancy needs a byte-diff against a wire capture of a working
//! wmiexec (impacket) against the same host; blind field-guessing is low-yield. Transport, auth,
//! stub dispatch, the MInterfacePointer conformant wrapper, and the OBJREF parse are all proven; the
//! activation-property *contents* are the open item. Stages 2–3 are gated on Stage 1 completing.

use crate::dcom::{orpc_this, IID_ISYSTEM_ACTIVATOR};
use crate::ndr::{NdrDecoder, NdrEncoder};
use crate::transport::RpcTcp;
use crate::{Result, RpcError, Syntax};
use windows_sddl::sid::Guid;

// ---- Activation-property CLSIDs (MS-DCOM §1.9) ---------------------------------------------------
const CLSID_ACTIVATION_PROPERTIES_IN: &str = "00000338-0000-0000-c000-000000000046";
const IID_IACTIVATION_PROPERTIES_IN: &str = "000001a2-0000-0000-c000-000000000046";
const CLSID_INSTANTIATION_INFO: &str = "000001ab-0000-0000-c000-000000000046";
const CLSID_ACTIVATION_CONTEXT_INFO: &str = "000001a5-0000-0000-c000-000000000046";
const CLSID_SERVER_LOCATION_INFO: &str = "000001a6-0000-0000-c000-000000000046";
const CLSID_SCM_REQUEST_INFO: &str = "000001aa-0000-0000-c000-000000000046";
const CLSID_SECURITY_INFO: &str = "000001a4-0000-0000-c000-000000000046";
const CLSID_SPECIAL_SYSTEM_PROPERTIES: &str = "000001b9-0000-0000-c000-000000000046";

/// ncacn_ip_tcp protocol-sequence id used in the SCM request's requested protseqs.
const NCACN_IP_TCP: u16 = 0x07;
/// MSHCTX_DIFFERENTMACHINE — the marshaling context for a remote activation.
const MSHCTX_DIFFERENTMACHINE: u32 = 2;

fn guid_bytes(s: &str) -> [u8; 16] {
    Guid::parse(s).expect("valid guid").0
}

/// A 16-byte NDR type-serialization-v1 pickle header for a body of `body_len` bytes.
/// CommonTypeHeader (8) = {version 1, endian 0x10, hdrlen 8, filler 0xcccccccc}
/// PrivateHeader     (8) = {ObjectBufferLength = body_len, filler 0}.
fn pickle_header(body_len: usize) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = 0x01; // version
    h[1] = 0x10; // little-endian, ASCII char rep
    h[2] = 0x08; // common header length
    h[3] = 0x00;
    h[4..8].copy_from_slice(&0xcccc_ccccu32.to_le_bytes()); // filler
    h[8..12].copy_from_slice(&(body_len as u32).to_le_bytes()); // ObjectBufferLength
    // h[12..16] = 0 filler
    h
}

/// Wrap a struct body in its type-serialization pickle (16-byte header + body, 8-padded).
fn pickle(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + body.len() + 8);
    // ObjectBufferLength counts the body padded to an 8-byte multiple.
    let padded = (body.len() + 7) & !7;
    v.extend_from_slice(&pickle_header(padded));
    v.extend_from_slice(body);
    v.resize(16 + padded, 0);
    v
}

/// InstantiationInfoData (§2.2.22.2.2): the class to create + the IIDs requested.
fn instantiation_info(clsid: &str, iids: &[&str]) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.uuid(&guid_bytes(clsid)); // classId
    e.u32(0x14); // classCtx = CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER
    e.u32(0); // actvflags
    e.u32(0); // fIsSurrogate
    e.u32(iids.len() as u32); // cIID
    e.u32(0); // instFlag
    e.referent(); // pIID (unique ptr, non-null)
    e.u32(0); // thisSize (patched by server; 0 ok)
    e.u16(5); // clientCOMVersion major
    e.u16(7); // clientCOMVersion minor
    // deferred: conformant array of IIDs
    e.u32(iids.len() as u32); // max_count
    for iid in iids {
        e.uuid(&guid_bytes(iid));
    }
    pickle(&e.into_bytes())
}

/// ActivationContextInfoData (§2.2.22.2.5): all-null client/prototype contexts.
fn activation_context_info() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.u32(0); // clientOK
    e.u32(0); // bReserved1
    e.u32(0); // dwReserved1
    e.u32(0); // dwReserved2
    e.null_ptr(); // pIFDClientCtx (MInterfacePointer*)
    e.null_ptr(); // pIFDPrototypeCtx
    pickle(&e.into_bytes())
}

/// LocationInfoData (§2.2.22.2.6): no machine name, ids 0.
fn location_info() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.null_ptr(); // machineName (wchar_t*)
    e.u32(0); // processId
    e.u32(0); // apartmentId
    e.u32(0); // contextId
    pickle(&e.into_bytes())
}

/// SpecialPropertiesData (§2.2.22.2.3): default authn level, no session/partition.
fn special_properties() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.u32(0); // dwSessionId
    e.u32(0); // fRemoteThisSessionId
    e.u32(0); // fClientImpersonating
    e.u32(0); // fPartitionIDPresent
    e.u32(0); // dwDefaultAuthnLvl
    e.uuid(&[0u8; 16]); // guidPartition
    e.u32(0); // dwPRTFlags
    e.u32(0); // dwOrigClsctx
    e.u32(0); // dwFlags
    // Reserved: 8 reserved DWORDs (Reserved1[8] per §2.2.22.2.3 layout used by impacket).
    for _ in 0..8 {
        e.u32(0);
    }
    e.u64(0); // Reserved3 (ULONGLONG)
    pickle(&e.into_bytes())
}

/// SecurityInfoData (§2.2.22.2.4): default authn, no explicit server info.
fn security_info() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.u32(0); // dwAuthnFlags
    e.null_ptr(); // pServerInfo (COSERVERINFO*)
    e.null_ptr(); // pdwReserved
    pickle(&e.into_bytes())
}

/// ScmRequestInfoData (§2.2.22.2.7): one requested protseq (ncacn_ip_tcp), no remote bindings.
fn scm_request_info() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.null_ptr(); // pdwReserved
    e.referent(); // remoteRequest (customREMOTE_REQUEST_SCM_INFO*, non-null)
    // customREMOTE_REQUEST_SCM_INFO:
    e.u32(2); // ClientImpLevel = RPC_C_IMP_LEVEL_IMPERSONATE
    e.u16(1); // cRequestedProtseqs
    e.u16(0); // pad
    e.referent(); // pRequestedProtseqs (unique ptr → conformant array)
    e.u32(1); // max_count
    e.u16(NCACN_IP_TCP);
    pickle(&e.into_bytes())
}

/// Assemble the full activation-properties `OBJREF_CUSTOM` (MInterfacePointer bytes) for a
/// `RemoteCreateInstance` of `clsid` requesting `iids`.
fn activation_properties_in(clsid: &str, iids: &[&str]) -> Vec<u8> {
    // Property order + their CLSIDs.
    let props: [(&str, Vec<u8>); 6] = [
        (CLSID_SPECIAL_SYSTEM_PROPERTIES, special_properties()),
        (CLSID_INSTANTIATION_INFO, instantiation_info(clsid, iids)),
        (CLSID_ACTIVATION_CONTEXT_INFO, activation_context_info()),
        (CLSID_SECURITY_INFO, security_info()),
        (CLSID_SERVER_LOCATION_INFO, location_info()),
        (CLSID_SCM_REQUEST_INFO, scm_request_info()),
    ];
    let n = props.len();

    // CustomHeader body (before its own pickle header).
    let mut ch = NdrEncoder::new();
    ch.u32(0); // totalSize (patched below)
    ch.u32(0); // headerSize (patched below)
    ch.u32(0); // dwReserved
    ch.u32(MSHCTX_DIFFERENTMACHINE); // destCtx
    ch.u32(n as u32); // cIfs
    ch.uuid(&[0u8; 16]); // classInfoClsid = GUID_NULL
    ch.referent(); // pclsid (unique ptr → conformant CLSID array)
    ch.referent(); // pSizes (unique ptr → conformant DWORD array)
    ch.null_ptr(); // pdwReserved
    // deferred conformant arrays, in pointer order:
    ch.u32(n as u32); // pclsid max_count
    for (c, _) in &props {
        ch.uuid(&guid_bytes(c));
    }
    ch.u32(n as u32); // pSizes max_count
    for (_, blob) in &props {
        ch.u32(blob.len() as u32);
    }
    let mut custom_header = pickle(&ch.into_bytes());

    // ActivationBLOB = dwSize + dwReserved + CustomHeader(pickled) + each property(pickled).
    let mut props_bytes = Vec::new();
    for (_, blob) in &props {
        props_bytes.extend_from_slice(blob);
    }
    // Patch CustomHeader.totalSize (body off 0) and headerSize (body off 4): the SCM uses these to
    // walk the property blobs. headerSize = the pickled CustomHeader length; totalSize adds the
    // concatenated property data. (Pickle header is 16 bytes, so body offsets 0/4 → vec 16/20.)
    let header_size = custom_header.len() as u32;
    let total_size = header_size + props_bytes.len() as u32;
    custom_header[16..20].copy_from_slice(&total_size.to_le_bytes());
    custom_header[20..24].copy_from_slice(&header_size.to_le_bytes());

    let mut blob = Vec::new();
    let total = 8 + custom_header.len() + props_bytes.len();
    blob.extend_from_slice(&(total as u32).to_le_bytes()); // dwSize
    blob.extend_from_slice(&0u32.to_le_bytes()); // dwReserved
    blob.extend_from_slice(&custom_header);
    blob.extend_from_slice(&props_bytes);

    // Wrap the ActivationBLOB in an OBJREF_CUSTOM, then an MInterfacePointer.
    objref_custom(CLSID_ACTIVATION_PROPERTIES_IN, IID_IACTIVATION_PROPERTIES_IN, &blob)
}

/// OBJREF_CUSTOM (§2.2.18.6): `MEOW` signature, flags=OBJREF_CUSTOM(4), iid, then
/// {clsid, cbExtension=0, ObjectReferenceSize, pObjectData}. Returns just the OBJREF bytes — the
/// `abData` of the enclosing MInterfacePointer (marshaled by [`marshal_minterface_ptr`]).
fn objref_custom(clsid: &str, iid: &str, object_data: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(b"MEOW"); // signature 0x574f454d
    o.extend_from_slice(&4u32.to_le_bytes()); // flags = OBJREF_CUSTOM
    o.extend_from_slice(&guid_bytes(iid)); // iid
    o.extend_from_slice(&guid_bytes(clsid)); // OBJREF_CUSTOM.clsid
    o.extend_from_slice(&0u32.to_le_bytes()); // cbExtension
    o.extend_from_slice(&(object_data.len() as u32).to_le_bytes()); // ObjectReferenceSize
    o.extend_from_slice(object_data); // pObjectData
    o
}

/// Marshal an `MInterfacePointer*` [unique] parameter (§2.2.14): a pointer referent, then the
/// conformant struct — `max_count` (== ulCntData), the `ulCntData` field, and the `abData` bytes.
/// The missing `max_count` is what a naive struct write omits; the server faults nca_s_fault_ndr.
fn marshal_minterface_ptr(e: &mut NdrEncoder, abdata: &[u8]) {
    e.referent(); // non-null unique pointer
    e.u32(abdata.len() as u32); // conformant max_count
    e.u32(abdata.len() as u32); // ulCntData
    e.bytes(abdata);
    e.align(4);
}

/// The stub for `ISystemActivator::RemoteCreateInstance` (opnum 4): ORPCTHIS, a null pUnkOuter,
/// and the activation-properties MInterfacePointer (a unique pointer → the pickled blob).
pub fn remote_create_instance_stub(cid: &[u8; 16], clsid: &str, iids: &[&str]) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.bytes(&orpc_this(cid)); // ORPCTHIS
    e.null_ptr(); // pUnkOuter (MInterfacePointer*, null)
    marshal_minterface_ptr(&mut e, &activation_properties_in(clsid, iids)); // pActProperties
    e.into_bytes()
}

/// A returned standard object reference: the OXID/OID/IPID needed to reach the activated object.
#[derive(Debug, Clone, Default)]
pub struct StdObjRef {
    pub oxid: u64,
    pub oid: u64,
    pub ipid: [u8; 16],
}

/// Locate the first STDOBJREF inside a `RemoteCreateInstance` reply by anchoring on the `MEOW`
/// OBJREF signature with flags=OBJREF_STANDARD(1), then reading {flags,cPublicRefs(4)} + STDOBJREF
/// {flags(4),cPublicRefs(4),OXID(8),OID(8),IPID(16)}. Returns the interface's OXID/OID/IPID.
pub fn parse_stdobjref(reply: &[u8]) -> Result<StdObjRef> {
    let mut i = 0;
    while i + 8 <= reply.len() {
        if &reply[i..i + 4] == b"MEOW" {
            let flags = u32::from_le_bytes(reply[i + 4..i + 8].try_into().unwrap());
            if flags == 1 {
                // OBJREF_STANDARD: after signature(4)+flags(4)+iid(16) comes STDOBJREF.
                let s = i + 8 + 16;
                let mut d = NdrDecoder::new(&reply[s..]);
                let _std_flags = d.u32()?;
                let _public_refs = d.u32()?;
                let oxid = d.u64()?;
                let oid = d.u64()?;
                let ipid = d.uuid()?;
                return Ok(StdObjRef { oxid, oid, ipid });
            }
        }
        i += 1;
    }
    Err(RpcError::Protocol(
        "no OBJREF_STANDARD in RemoteCreateInstance reply".into(),
    ))
}

/// Trailing HRESULT hunt: RemoteCreateInstance returns the activation HRESULT near the reply tail.
/// A non-zero leading `hResult` in the ScmReplyInfoData signals activation failure.
pub fn activation_hresult(reply: &[u8]) -> i32 {
    // The ORPCTHAT + reply MInterfacePointer precede a small fixed tail; the final 4 bytes are the
    // call's own return HRESULT.
    reply
        .get(reply.len().wrapping_sub(4)..)
        .and_then(|b| b.try_into().ok())
        .map(i32::from_le_bytes)
        .unwrap_or(-1)
}

/// Stage 1 live: authenticated `RemoteCreateInstance` of `clsid` on `host` (ISystemActivator over
/// a sealed ncacn_ip_tcp:135 bind), requesting `iids`. Returns the activated object's StdObjRef
/// (OXID/OID/IPID — the handle Stage 2 resolves + binds) and the activation HRESULT.
pub async fn remote_create_instance(
    host: &str,
    domain: &str,
    user: &str,
    password: &str,
    workstation: &str,
    clsid: &str,
    iids: &[&str],
) -> Result<(StdObjRef, i32)> {
    let addr = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:135")
    };
    let reply = remote_create_instance_raw(host, domain, user, password, workstation, clsid, iids).await?;
    let hr = activation_hresult(&reply);
    let obj = parse_stdobjref(&reply)?;
    Ok((obj, hr))
}

/// As [`remote_create_instance`] but returns the raw decrypted reply stub (for parsing / debugging
/// the ScmReplyInfoData + interface OBJREFs).
pub async fn remote_create_instance_raw(
    host: &str,
    domain: &str,
    user: &str,
    password: &str,
    workstation: &str,
    clsid: &str,
    iids: &[&str],
) -> Result<Vec<u8>> {
    let addr = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:135")
    };
    let mut rpc = RpcTcp::connect(&addr).await?;
    rpc.bind_sealed(
        Syntax::new(IID_ISYSTEM_ACTIVATOR, 0, 0),
        domain,
        user,
        password,
        workstation,
    )
    .await?;
    let cid = [0x5Au8; 16]; // causality id for this logical call chain
    rpc.call_sealed(4, &remote_create_instance_stub(&cid, clsid, iids))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pickle_header_shape() {
        let h = pickle_header(0x40);
        assert_eq!(&h[0..4], &[0x01, 0x10, 0x08, 0x00]);
        assert_eq!(&h[4..8], &0xcccc_ccccu32.to_le_bytes());
        assert_eq!(&h[8..12], &0x40u32.to_le_bytes());
    }

    #[test]
    fn objref_custom_signature_and_len() {
        let o = objref_custom(
            CLSID_ACTIVATION_PROPERTIES_IN,
            IID_IACTIVATION_PROPERTIES_IN,
            &[0xAA; 8],
        );
        assert_eq!(&o[0..4], b"MEOW");
        assert_eq!(&o[4..8], &4u32.to_le_bytes()); // OBJREF_CUSTOM flags
        let n = o.len();
        // trailer: cbExtension(0) + ObjectReferenceSize(8) + 8 data bytes.
        assert_eq!(&o[n - 16..n - 12], &0u32.to_le_bytes()); // cbExtension
        assert_eq!(&o[n - 12..n - 8], &8u32.to_le_bytes()); // ObjectReferenceSize
        assert_eq!(&o[n - 8..], &[0xAA; 8]); // pObjectData
    }

    #[test]
    fn minterface_ptr_has_conformant_prefix() {
        let mut e = NdrEncoder::new();
        marshal_minterface_ptr(&mut e, &[0xBB; 12]);
        let b = e.into_bytes();
        assert_ne!(u32::from_le_bytes(b[0..4].try_into().unwrap()), 0); // referent
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 12); // max_count
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 12); // ulCntData
    }

    #[test]
    fn instantiation_info_has_class_and_iid() {
        let b = instantiation_info(
            "8bc3f05e-d86b-11d0-a075-00c04fb68820",
            &["f309ad18-d86a-11d0-a075-00c04fb68820"],
        );
        // pickle header + body; classId GUID begins right after the 16-byte header.
        assert_eq!(&b[16..20], &guid_bytes("8bc3f05e-d86b-11d0-a075-00c04fb68820")[0..4]);
        // cIID = 1 lives at header(16) + classId(16)+classCtx(4)+actv(4)+surrogate(4) = offset 44.
        assert_eq!(&b[44..48], &1u32.to_le_bytes());
    }

    // Live Stage-1: activate WbemLevel1Login on the lab DC and parse the returned OBJREF.
    //   ADH_DC=192.168.10.22 ADH_DOMAIN=TESTLAB ADH_USER=administrator ADH_PASS=… \
    //     cargo test -p dcerpc --lib dcom_wmi::tests::remote_create_instance_live -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "live DC"]
    async fn remote_create_instance_live() {
        let (Ok(dc), Ok(dom), Ok(user), Ok(pass)) = (
            std::env::var("ADH_DC"),
            std::env::var("ADH_DOMAIN"),
            std::env::var("ADH_USER"),
            std::env::var("ADH_PASS"),
        ) else {
            return;
        };
        use crate::dcom::{CLSID_WBEM_LEVEL1_LOGIN, IID_IWBEM_LEVEL1_LOGIN};
        let reply = remote_create_instance_raw(
            &dc,
            &dom,
            &user,
            &pass,
            "ADHAMMER",
            CLSID_WBEM_LEVEL1_LOGIN,
            &[IID_IWBEM_LEVEL1_LOGIN],
        )
        .await
        .expect("activation call");
        println!("reply {} bytes:", reply.len());
        for (i, ch) in reply.chunks(16).enumerate() {
            let hex: Vec<String> = ch.iter().map(|b| format!("{b:02x}")).collect();
            println!("  {:04x}: {}", i * 16, hex.join(" "));
        }
        // count MEOW signatures + their flags to locate the returned interface OBJREF(s).
        let mut i = 0;
        while i + 8 <= reply.len() {
            if &reply[i..i + 4] == b"MEOW" {
                let f = u32::from_le_bytes(reply[i + 4..i + 8].try_into().unwrap());
                println!("  MEOW @0x{i:04x} flags={f}");
            }
            i += 1;
        }
    }

    #[test]
    fn stdobjref_parse_roundtrip() {
        // Build a minimal OBJREF_STANDARD and read it back.
        let mut r = Vec::new();
        r.extend_from_slice(b"MEOW");
        r.extend_from_slice(&1u32.to_le_bytes()); // OBJREF_STANDARD
        r.extend_from_slice(&[0x11; 16]); // iid
        r.extend_from_slice(&0u32.to_le_bytes()); // std flags
        r.extend_from_slice(&5u32.to_le_bytes()); // public refs
        r.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes()); // oxid
        r.extend_from_slice(&0x99AA_BBCC_DDEE_FF00u64.to_le_bytes()); // oid
        r.extend_from_slice(&[0x22; 16]); // ipid
        let s = parse_stdobjref(&r).unwrap();
        assert_eq!(s.oxid, 0x1122_3344_5566_7788);
        assert_eq!(s.oid, 0x99AA_BBCC_DDEE_FF00);
        assert_eq!(s.ipid, [0x22; 16]);
    }
}
