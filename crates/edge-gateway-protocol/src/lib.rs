//! Version 1 gateway wire contract. Additive protobuf fields preserve compatibility.
#![forbid(unsafe_code)]
pub const PROTOCOL_VERSION: u32 = 1;

include!(concat!(env!("OUT_DIR"), "/apollo.edge.rs"));
