//! NDR (Network Data Representation) marshaling.
//!
//! Extracted into the standalone [`ms-ndr`](https://crates.io/crates/ms-ndr) crate and
//! re-exported here so every interface module keeps using `crate::ndr::{NdrEncoder,
//! NdrDecoder}` unchanged. Decoder errors (`NdrError`) convert into [`crate::RpcError`]
//! via `?` (see the `From` impl in `lib.rs`).

pub use ms_ndr::{NdrDecoder, NdrEncoder, NdrError};
