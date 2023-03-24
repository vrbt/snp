// SPDX-License-Identifier: Apache-2.0

pub mod builtin;
pub mod ecdsa;

#[cfg(feature = "openssl")]
use openssl::*;

#[cfg(feature = "openssl")]
struct Body;

use std::io::Result;

#[cfg(feature = "openssl")]
/// An interface for types that may contain entities such as
/// signatures that must be verified.
pub trait Verifiable {
    /// An output type for successful verification.
    type Output;

    /// Self-verifies signatures.
    fn verify(self) -> Result<Self::Output>;
}

#[cfg(feature = "openssl")]
/// An interface for types that can sign another type (i.e., a certificate).
pub trait Signer<T> {
    /// The now-signed type.
    type Output;

    /// Signs the target.
    fn sign(&self, target: &mut T) -> Result<Self::Output>;
}

#[cfg(feature = "openssl")]
struct Signature {
    id: Option<[u8; 16]>,
    sig: Vec<u8>,
    kind: pkey::Id,
    hash: hash::MessageDigest,
    usage: Usage,
}

#[cfg(feature = "openssl")]
/// Represents a private key.
pub struct PrivateKey<U> {
    id: Option<[u8; 16]>,
    key: pkey::PKey<pkey::Private>,
    hash: hash::MessageDigest,
    usage: U,
}

#[cfg(feature = "openssl")]
struct PublicKey<U> {
    id: Option<[u8; 16]>,
    key: pkey::PKey<pkey::Public>,
    hash: hash::MessageDigest,
    usage: U,
}

/// Denotes a certificate's usage.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Usage(u32);

impl Usage {
    /// Owner Certificate Authority.
    pub const OCA: Usage = Usage(0x1001u32.to_le());

    /// AMD Root Key.
    pub const ARK: Usage = Usage(0x0000u32.to_le());

    /// AMD Signing Key.
    pub const ASK: Usage = Usage(0x0013u32.to_le());

    /// Chip Endorsement Key.
    pub const CEK: Usage = Usage(0x1004u32.to_le());

    /// Platform Endorsement Key.
    pub const PEK: Usage = Usage(0x1002u32.to_le());

    /// Platform Diffie-Hellman.
    pub const PDH: Usage = Usage(0x1003u32.to_le());

    const INV: Usage = Usage(0x1000u32.to_le());
}

impl std::fmt::Display for Usage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Usage::OCA => "OCA",
                Usage::PEK => "PEK",
                Usage::PDH => "PDH",
                Usage::CEK => "CEK",
                Usage::ARK => "ARK",
                Usage::ASK => "ASK",
                Usage::INV => "INV",
                _ => return Err(std::fmt::Error),
            }
        )
    }
}

pub(crate) trait FromLe: Sized {
    fn from_le(value: &[u8]) -> Result<Self>;
}

pub(crate) trait AsLeBytes<T> {
    fn as_le_bytes(&self) -> T;
}

#[cfg(feature = "openssl")]
impl FromLe for openssl::bn::BigNum {
    #[inline]
    fn from_le(value: &[u8]) -> Result<Self> {
        Ok(Self::from_slice(
            &value.iter().rev().cloned().collect::<Vec<_>>(),
        )?)
    }
}

#[cfg(feature = "openssl")]
impl AsLeBytes<[u8; 72]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 72] {
        let mut buf = [0u8; 72];

        for (i, b) in self.to_vec().into_iter().rev().enumerate() {
            buf[i] = b;
        }

        buf
    }
}

#[cfg(feature = "openssl")]
impl AsLeBytes<[u8; 512]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 512] {
        let mut buf = [0u8; 512];

        for (i, b) in self.to_vec().into_iter().rev().enumerate() {
            buf[i] = b;
        }

        buf
    }
}
