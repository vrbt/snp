// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

//!
//! # Platform Attestation using VirTEE/SNP
//!
//! The [VirTEE/snp](https://github.com/virtee/snp) crate offers a rust-friendly, simple-to-use API for interfacing with the AMD Secure Processor included within 3rd Generation -- or newer -- AMD EPYC processors.
//!
//! Examples, use-cases, and potential solutions:
//!
//! - [`Platform Owners`](crate::firmware::host)
//!
//! - [`Guest Owners`](crate::firmware::guest)
//!

mod util;

/// Includes built-in AMD certificates for verification of the root of trust.
pub mod certs;

/// Errors which may be encountered when interacting with this API.
pub mod error;

/// Structures and implementations for communicating with the AMD Secure Processor.
pub mod firmware;

/// Structures and implementations for guest management of SNP machines.
pub mod launch;
