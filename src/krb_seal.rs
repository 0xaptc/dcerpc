//! Kerberos GSS-API `WRAP` token (RFC 4121 §4.2) primitives for sealed DCE/RPC binds.
//!
//! Layering mirrors the NTLMSSP path in [`crate::transport`]:
//!
//! ```text
//!   sender:   plaintext PDU  →  KrbSealer::seal_pdu  →  (sealed_stub, auth_value)
//!   wire  :   pdu.rs::build_request_sealed_krb inserts sealed_stub + auth_value
//!   receiver: pdu.rs::split_sealed_response_krb hands back the same triple
//!             →  KrbSealer::unseal_pdu  →  plaintext PDU
//! ```
//!
//! This module ships the **wire-format** half — the 16-byte WRAP header codec
//! ([`WrapToken`]) plus the [`KrbSealer`] trait a Kerberos-crypto crate implements.
//!
//! The concrete AES-CTS-HMAC-SHA1-96 sealer (RFC 3961 `DK` + `n-fold` + `E()` + the DCE-style
//! WRAP layout of RFC 4121 §4.2 / MS-KILE §3.4.5.4.1) is **not** in this crate — it lives with
//! the Kerberos client that already holds the TGS session key. That crate uses `picky-krb`'s
//! `CipherSuite::Aes256CtsHmacSha196` for the underlying `E()` function.
//!
//! Bounded-alloc: every parser here rejects `usize::MAX`-shaped attacker inputs before any
//! allocation (see the `hostile_*` tests).

use crate::{Result, RpcError};

/// WRAP token TOK_ID (RFC 4121 §4.2.6.2): the 2-byte big-endian tag identifying a wrap token.
pub const TOK_ID_WRAP: u16 = 0x0504;

/// WRAP header size: 2 (TOK_ID) + 1 (Flags) + 1 (Filler) + 2 (EC) + 2 (RRC) + 8 (SND_SEQ) = 16.
pub const WRAP_HEADER_LEN: usize = 16;

/// AES-CTS-HMAC-SHA1-96 checksum length (RFC 3962 §3): HMAC-SHA1 truncated to 12 octets.
pub const AES_SHA1_CHECKSUM_LEN: usize = 12;

/// AES-CTS-HMAC-SHA1-96 DCE-style WRAP auth_value length: 16 (WRAP header) + 12 (HMAC).
pub const AES_SHA1_AUTH_VALUE_LEN: usize = WRAP_HEADER_LEN + AES_SHA1_CHECKSUM_LEN;

pub mod wrap_flags {
    /// Bit 0. Set when the token was emitted by the acceptor (server → client).
    pub const SENT_BY_ACCEPTOR: u8 = 0x01;
    /// Bit 1. Set when the payload is sealed (confidentiality); clear = MIC token only.
    pub const SEALED: u8 = 0x02;
    /// Bit 2. Set when the sealer used a subkey from the AP-REP's acceptor-subkey slot.
    pub const ACCEPTOR_SUBKEY: u8 = 0x04;
}

/// The 16-byte WRAP token header (RFC 4121 §4.2.6.2). All multi-byte fields are big-endian —
/// unlike the surrounding little-endian DCE/RPC PDU, so getting the byte order right at this
/// boundary matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrapToken {
    pub flags: u8,
    /// Extra Count — bytes of trailing filler included in the encrypted payload before the
    /// header. Always 0 for AES-CTS (which does not need block-alignment padding).
    pub ec: u16,
    /// Right Rotation Count — bytes the ciphertext is rotated right by after encryption.
    /// DCE-style RPC uses RRC = 0 and treats the E() output as `data-ciphertext || checksum`.
    pub rrc: u16,
    /// Sequence number, monotonically incremented per WRAP token in each direction.
    pub snd_seq: u64,
}

impl WrapToken {
    /// New WRAP header for a sealed payload.
    ///
    /// `sent_by_acceptor = false` for client → server tokens; `true` for the server's replies.
    /// `acceptor_subkey` reflects whether the AP-REP negotiated an acceptor subkey to use as
    /// the sealing key — set it when the ticket exchange delivered one.
    pub fn sealed(sent_by_acceptor: bool, acceptor_subkey: bool, snd_seq: u64) -> Self {
        let mut flags = wrap_flags::SEALED;
        if sent_by_acceptor {
            flags |= wrap_flags::SENT_BY_ACCEPTOR;
        }
        if acceptor_subkey {
            flags |= wrap_flags::ACCEPTOR_SUBKEY;
        }
        WrapToken {
            flags,
            ec: 0,
            rrc: 0,
            snd_seq,
        }
    }

    /// Encode as the on-wire 16-byte header (all multi-byte fields big-endian).
    pub fn encode(&self) -> [u8; WRAP_HEADER_LEN] {
        let mut out = [0u8; WRAP_HEADER_LEN];
        out[0..2].copy_from_slice(&TOK_ID_WRAP.to_be_bytes());
        out[2] = self.flags;
        out[3] = 0xFF; // Filler
        out[4..6].copy_from_slice(&self.ec.to_be_bytes());
        out[6..8].copy_from_slice(&self.rrc.to_be_bytes());
        out[8..16].copy_from_slice(&self.snd_seq.to_be_bytes());
        out
    }

    /// Parse a 16-byte WRAP header. Rejects wrong TOK_ID, wrong filler, and reserved flag bits.
    /// Also rejects a short input — nothing else in the auth_value can be trusted otherwise.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < WRAP_HEADER_LEN {
            return Err(RpcError::Underrun {
                need: WRAP_HEADER_LEN,
                pos: buf.len(),
            });
        }
        let tok_id = u16::from_be_bytes([buf[0], buf[1]]);
        if tok_id != TOK_ID_WRAP {
            return Err(RpcError::Protocol(format!(
                "WRAP token TOK_ID {tok_id:#06x} != 0x0504"
            )));
        }
        let flags = buf[2];
        // Bits 3..7 are reserved and MUST be zero (RFC 4121 §4.2.2).
        if flags & 0xF8 != 0 {
            return Err(RpcError::Protocol(format!(
                "WRAP token reserved flag bits set: {flags:#04x}"
            )));
        }
        if buf[3] != 0xFF {
            return Err(RpcError::Protocol(format!(
                "WRAP token filler {:#04x} != 0xFF",
                buf[3]
            )));
        }
        Ok(WrapToken {
            flags,
            ec: u16::from_be_bytes([buf[4], buf[5]]),
            rrc: u16::from_be_bytes([buf[6], buf[7]]),
            snd_seq: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
        })
    }

    pub fn is_sealed(&self) -> bool {
        self.flags & wrap_flags::SEALED != 0
    }
    pub fn is_from_acceptor(&self) -> bool {
        self.flags & wrap_flags::SENT_BY_ACCEPTOR != 0
    }
    pub fn uses_acceptor_subkey(&self) -> bool {
        self.flags & wrap_flags::ACCEPTOR_SUBKEY != 0
    }
}

/// Per-session Kerberos sealer: mirrors [`ntlmssp::SealState`] for the NTLM path.
///
/// One state per connection holds the sealing key (TGS session key or AP-REP-negotiated subkey)
/// plus the two directional sequence counters, so the client emits `client_seq`-tagged tokens
/// and validates server replies against `server_seq`. Implementations live outside `dcerpc` —
/// the crate carrying picky-krb (or an alternative Kerberos crypto backend) wires this up
/// against `CipherSuite::Aes256CtsHmacSha196` and its `E()` / `D()` primitives.
pub trait KrbSealer {
    /// Seal a plaintext outgoing DCE/RPC PDU.
    ///
    /// `sign_over` is the whole PDU minus the trailing auth_value (i.e. header + body + the
    /// 8-byte sec_trailer, with the stub still plaintext). `stub` is the aligned plaintext
    /// stub bytes to encrypt in-place. Returns `(sealed_stub, auth_value)` where
    /// `sealed_stub.len() == stub.len()` and `auth_value.len() == self.auth_value_len()`.
    ///
    /// For DCE-style AES-CTS-HMAC-SHA1-96 that is 16 (WRAP header) + 12 (HMAC) = 28 bytes.
    fn seal_pdu(&mut self, sign_over: &[u8], stub: &[u8]) -> (Vec<u8>, Vec<u8>);

    /// Unseal an incoming (server → client) PDU.
    ///
    /// `pdu_no_auth` is the response with the sealed stub still in place and the trailing
    /// auth_value stripped; the sealed stub occupies `stub_off .. stub_off + stub_len`.
    /// `auth_value` is the trailing WRAP-token bytes (`self.auth_value_len()`). Returns the
    /// decrypted stub (still padded) or an `RpcError::Protocol` on MAC failure or malformed
    /// input.
    fn unseal_pdu(
        &mut self,
        pdu_no_auth: &[u8],
        stub_off: usize,
        stub_len: usize,
        auth_value: &[u8],
    ) -> Result<Vec<u8>>;

    /// Bytes this sealer emits as the RPC auth_value (goes into the sec_trailer's
    /// `auth_length`). Constant per session.
    fn auth_value_len(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_token_roundtrip() {
        let t = WrapToken::sealed(false, true, 0x0102_0304_0506_0708);
        let enc = t.encode();
        assert_eq!(&enc[0..2], &[0x05, 0x04]); // TOK_ID big-endian
        assert_eq!(enc[2], wrap_flags::SEALED | wrap_flags::ACCEPTOR_SUBKEY);
        assert_eq!(enc[3], 0xFF); // filler
        assert_eq!(&enc[8..16], &0x0102_0304_0506_0708u64.to_be_bytes());
        let dec = WrapToken::decode(&enc).unwrap();
        assert_eq!(dec, t);
    }

    #[test]
    fn wrap_token_server_ack_direction() {
        // Server → client reply carries SentByAcceptor; snd_seq starts at 0 for that direction.
        let t = WrapToken::sealed(true, false, 0);
        let enc = t.encode();
        assert_eq!(enc[2], wrap_flags::SEALED | wrap_flags::SENT_BY_ACCEPTOR);
        let dec = WrapToken::decode(&enc).unwrap();
        assert!(dec.is_from_acceptor());
        assert!(dec.is_sealed());
        assert!(!dec.uses_acceptor_subkey());
    }

    #[test]
    fn hostile_short_header_rejected() {
        // A 15-byte buffer (one short of the WRAP header) must fail before any subfield read.
        let err = WrapToken::decode(&[0xFFu8; 15]).unwrap_err();
        match err {
            RpcError::Underrun { need, pos } => {
                assert_eq!(need, WRAP_HEADER_LEN);
                assert_eq!(pos, 15);
            }
            other => panic!("expected Underrun, got {other:?}"),
        }
    }

    #[test]
    fn hostile_wrong_tok_id_rejected() {
        // MIC token TOK_ID (0x0404) in a slot advertised as WRAP → must reject.
        let mut buf = [0u8; WRAP_HEADER_LEN];
        buf[0..2].copy_from_slice(&0x0404u16.to_be_bytes());
        buf[3] = 0xFF;
        match WrapToken::decode(&buf).unwrap_err() {
            RpcError::Protocol(m) => assert!(m.contains("TOK_ID")),
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn hostile_reserved_flag_bits_rejected() {
        // Reserved bits 3..7 set → reject rather than trust the header. Guards against a
        // future-flag downgrade or a fuzz-corrupted header masquerading as a WRAP.
        let mut buf = [0u8; WRAP_HEADER_LEN];
        buf[0..2].copy_from_slice(&TOK_ID_WRAP.to_be_bytes());
        buf[2] = 0xF8; // top 5 bits all reserved
        buf[3] = 0xFF;
        match WrapToken::decode(&buf).unwrap_err() {
            RpcError::Protocol(m) => assert!(m.contains("reserved flag")),
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn hostile_bad_filler_rejected() {
        // Filler must be exactly 0xFF (RFC 4121 §4.2.6.2). 0x00 here would silently pass a
        // structural check; the explicit compare catches it.
        let mut buf = [0u8; WRAP_HEADER_LEN];
        buf[0..2].copy_from_slice(&TOK_ID_WRAP.to_be_bytes());
        buf[2] = wrap_flags::SEALED;
        buf[3] = 0x00;
        match WrapToken::decode(&buf).unwrap_err() {
            RpcError::Protocol(m) => assert!(m.contains("filler")),
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    /// A deliberately-hostile RRC field (`u16::MAX`) parses without panicking (structural
    /// decode is pure arithmetic on fixed offsets) and the caller — whichever concrete
    /// [`KrbSealer`] implements the rotation — is responsible for bounds-checking it before
    /// touching a Vec.
    #[test]
    fn max_rrc_field_decodes_without_alloc() {
        let mut buf = [0u8; WRAP_HEADER_LEN];
        buf[0..2].copy_from_slice(&TOK_ID_WRAP.to_be_bytes());
        buf[2] = wrap_flags::SEALED;
        buf[3] = 0xFF;
        buf[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        let t = WrapToken::decode(&buf).unwrap();
        assert_eq!(t.rrc, u16::MAX);
        // A concrete sealer's rotate step must saturate/mod against auth_value.len(), not
        // trust this value to fit any real buffer.
    }

    /// A mock sealer that stubs the crypto: seal = XOR-with-a-fixed-key + fake-HMAC. Its only
    /// job is to prove [`KrbSealer`]'s contract round-trips at the trait boundary so the
    /// wire-format pipeline can be exercised end-to-end before the real crypto lands.
    struct XorSealer {
        key: u8,
        client_seq: u64,
        server_seq: u64,
    }
    impl KrbSealer for XorSealer {
        fn seal_pdu(&mut self, _sign_over: &[u8], stub: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let sealed: Vec<u8> = stub.iter().map(|b| b ^ self.key).collect();
            let mut av = WrapToken::sealed(false, false, self.client_seq)
                .encode()
                .to_vec();
            av.extend_from_slice(&[0xABu8; AES_SHA1_CHECKSUM_LEN]); // stand-in HMAC
            self.client_seq = self.client_seq.wrapping_add(1);
            (sealed, av)
        }
        fn unseal_pdu(
            &mut self,
            pdu_no_auth: &[u8],
            stub_off: usize,
            stub_len: usize,
            auth_value: &[u8],
        ) -> Result<Vec<u8>> {
            if auth_value.len() != AES_SHA1_AUTH_VALUE_LEN {
                return Err(RpcError::Protocol(format!(
                    "auth_value length {} != {AES_SHA1_AUTH_VALUE_LEN}",
                    auth_value.len()
                )));
            }
            let tok = WrapToken::decode(&auth_value[..WRAP_HEADER_LEN])?;
            if tok.snd_seq != self.server_seq {
                return Err(RpcError::Protocol(format!(
                    "WRAP seq {} != expected {}",
                    tok.snd_seq, self.server_seq
                )));
            }
            let sealed =
                pdu_no_auth
                    .get(stub_off..stub_off + stub_len)
                    .ok_or(RpcError::Underrun {
                        need: stub_off + stub_len,
                        pos: pdu_no_auth.len(),
                    })?;
            let plain: Vec<u8> = sealed.iter().map(|b| b ^ self.key).collect();
            self.server_seq = self.server_seq.wrapping_add(1);
            Ok(plain)
        }
        fn auth_value_len(&self) -> usize {
            AES_SHA1_AUTH_VALUE_LEN
        }
    }

    #[test]
    fn trait_roundtrip_via_mock_sealer() {
        let mut client = XorSealer {
            key: 0x5A,
            client_seq: 0,
            server_seq: 0,
        };
        let mut server = XorSealer {
            key: 0x5A,
            client_seq: 0,
            server_seq: 0,
        };
        // Simulate a client → server flow: seal, transmit, unseal on the other side. The mock
        // proves that (sealed_stub, auth_value) shapes round-trip through the trait cleanly.
        let stub = b"NDR-marshaled-request-stub-payload".to_vec();
        let sign_over = b"pdu-header + body + sec_trailer".to_vec();
        let (sealed, av) = client.seal_pdu(&sign_over, &stub);
        assert_eq!(sealed.len(), stub.len());
        assert_eq!(av.len(), AES_SHA1_AUTH_VALUE_LEN);

        // Rebuild the server's view of the PDU-minus-auth: sign_over + sealed stub sitting at
        // the tail (contiguous with sign_over, matching how build_request_sealed_krb lays it).
        let mut pdu_no_auth = sign_over.clone();
        let stub_off = pdu_no_auth.len();
        pdu_no_auth.extend_from_slice(&sealed);
        let out = server
            .unseal_pdu(&pdu_no_auth, stub_off, stub.len(), &av)
            .unwrap();
        assert_eq!(out, stub);
    }

    #[test]
    fn trait_rejects_wrong_auth_value_length() {
        // A `u32::MAX`-shaped auth_length that stripped only 4 bytes must not decode as a
        // valid WRAP — the impl is required to hard-reject before touching the buffer.
        let mut sealer = XorSealer {
            key: 0,
            client_seq: 0,
            server_seq: 0,
        };
        let err = sealer.unseal_pdu(&[0u8; 40], 8, 16, &[0u8; 4]).unwrap_err();
        match err {
            RpcError::Protocol(m) => assert!(m.contains("length")),
            other => panic!("expected Protocol, got {other:?}"),
        }
    }
}
