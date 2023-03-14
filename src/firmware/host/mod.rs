// SPDX-License-Identifier: Apache-2.0

//! # Host / Platform Owner
//!
//! The Platform Owner, or Host, may still perform all of the legacy SEV functions, but now also has the capability to:
//!
//! - Request an SNP Platform Status
//! - Load policy configurations and/or certificate chains into hypervisor memory.
//! - Request copies of the current policy configuration and/or certificate chains stored in hypervisor memory.
//!
//!
//! ### Operating System Requirements:
//!
//!
//! Development for SEV-SNP is on-going, and is estimated to be committed into the upstream Linux Kernel by version 6.3. Until it is upstream, it is recommended to use a branch from the AMD fork of the Linux kernel. At the time of writing, this is [sev-snp-iommu-avic_5.19-rc6_v4](https://github.com/AMDESE/linux/tree/sev-snp-iommu-avic_5.19-rc6_v4).
//!
//!
//! ### Hardware / Firmware Requirements:
//!
//!
//! In order to use [snp](https://github.com/virtee/snp), it is recommended to have the firmware up-to-date -- ([version 1.54](https://developer.amd.com/wp-content/resources/amd_sev_fam19h_model0xh_1.54.01.zip)) at time of writing.
//!
//!
//! ### Software Requirements:
//!
//!
//! If neither the guest owner or platform owner needs to:
//!
//!
//! - Validate the identity block provided by a guest to be included within an attestation report
//! - Validate the Kernel, initrd, or cmdline parameters (only OVMF / EDK II)
//!
//!
//! Then it is recommended to use upstream OVMF / EDK II and Qemu version 7.1.
//!
//! If either of the aforementioned are needed use the following:
//!
//! - [OVMF / EDK II - SNP Kernel Hashes v3](https://github.com/confidential-containers-demo/edk2/tree/snp-kernel-hashes-v3)
//! - [Qemu - SNP Kernel Hashes v3](https://github.com/confidential-containers-demo/qemu/tree/snp-kernel-hashes-v3)
//!
//!
//! Each of these branches contain the necessary patches to address those needs.
//!
//!
//! # Examples:
//!
//! ### Loading and Requesting Policy and/or Certificate Chain:
//!
//!
//! A Platform Owner my decide to store policies and certificate-chains into hypervisor memory for Guest Owner ease-of-use. Further, this mitigates the potential issues found from attempting to access the AMD Key Distribution Server (KDS); which is rate-limited.
//!
//!
//! #### Configuration Loading Example:
//!
//!
//! 1. Include the `snp` crate into your Rust project.
//!
//!     ```no_run
//!     // Import library
//!     use snp::firmware::host::types::*;
//!     ```
//!
//!
//!
//! 2. Read the bytes of the certificates which will be stored in Hypervisor memory. This could be done with `include_bytes!()`, or by some other means. This example will use `include_bytes!()`.
//!
//!     ```no_run
//!     // Read certificate bytes. This could be done by reading bytes from a file
//!     // with `include_bytes!()` or by some other means.
//!     pub const ARK: &[u8] = include_bytes!("ark.pem");
//!     pub const ASK: &[u8] = include_bytes!("ask.pem");
//!     pub const VCEK: &[u8] = include_bytes!("vcek.pem");
//!     ```
//!
//! 3. Create a configuration for when guests request an extended report:
//!
//!     - OPTION A: Certificates Only
//!
//!         ```no_run
//!         // Generate a vector of certificates to store in hypervisor memory.
//!         let certificates: Vec<CertTableEntry> = vec![
//!             CertTableEntry::new(SnpCertType::ARK, ARK.to_vec()),
//!             CertTableEntry::new(SnpCertType::ASK, ASK.to_vec()),
//!             CertTableEntry::new(SnpCertType::VCEK, VCEK.to_vec()),
//!         ];
//!
//!         // Call the `update_certs_only` constructor to generate the extended configuration.
//!         let ext_config: SnpExtConfig = SnpExtConfig::update_certs_only(certificates);
//!         ```
//!
//!
//!     - OPTION B: Configuration Only
//!
//!
//!         ```no_run
//!         // Specify the desired configuration
//!         let configuration: SnpConfig = SnpConfig::new(
//!             TcbVersion::new(3, 0, 10, 169),
//!             0,
//!         );
//!
//!         // Call the `update_config_only` constructor to generate the extended configuration.
//!         let ext_config: SnpExtConfig = SnpExtConfig::update_config_only(configuration);
//!         ```
//!
//!
//!     - OPTION C: Configuration and Certificates
//!
//!
//!         ```no_run
//!         // Specify the desired configuration
//!         let configuration: SnpConfig = SnpConfig::new(
//!             TcbVersion::new(3, 0, 10, 169),
//!             0,
//!         );
//!
//!         // Generate a vector of certificates to store in hypervisor memory.
//!         let certificates: Vec<CertTableEntry> = vec![
//!             CertTableEntry::new(SnpCertType::ARK, ARK.to_vec()),
//!             CertTableEntry::new(SnpCertType::ASK, ASK.to_vec()),
//!             CertTableEntry::new(SnpCertType::VCEK, VCEK.to_vec()),
//!         ];
//!
//!         // Call the `new` constructor to generate the extended configuration.
//!         let ext_config: SnpExtConfig = SnpExtConfig::new(configuration, certificates);
//!         ```
//!
//! 4. Connect to the firmware and forward the extended request to the AMD Secure Processor:
//!
//!     ```no_run
//!     // Open a connection to the firmware.
//!     let mut fw: Firmware = Firmware::open().unwrap();
//!
//!     // Forward the certificates to the PSP to be loaded.
//!     if let Err(error) = fw.snp_set_ext_config(&ext_config) {
//!         // Handle an error if one is encountered.
//!         ...
//!     }
//!     ```
//!
//!
//! #### Requesting Example:
//!
//!
//! 1. Connect to the firmware and request for the current configuration:
//!
//!
//!     ```no_run
//!     // Open a connection to the firmware.
//!     let mut fw: Firmware = Firmware::open().unwrap();
//!
//!     // Request the current configuration.
//!     let current_configuration: SnpExtConfig = fw.snp_get_ext_config().unwrap();
//!     ```
//!
//!

pub mod types;

use std::{
    fs::{File, OpenOptions},
    os::fd::{AsRawFd, RawFd},
};

use crate::error::*;
use types::*;

use FFI::ioctl::*;

use self::types::FFI::types::TryFromConfig;

///
/// This is a façade function to give public access to the FFI parse table
/// function.
///
pub fn parse_table(data: RawData) -> Result<Vec<CertTableEntry>, uuid::Error> {
    match data {
        RawData::Pointer(pointer) => unsafe {
            FFI::types::CertTableEntry::parse_table(pointer as *mut FFI::types::CertTableEntry)
        },
        RawData::Vector(vector) => unsafe {
            FFI::types::CertTableEntry::parse_table(
                vector.as_ptr() as *mut FFI::types::CertTableEntry
            )
        },
    }
}

/// A handle to the SEV platform.
pub struct Firmware(File);

impl Firmware {
    /// Create a handle to the SEV platform via `/dev/sev`.
    ///
    /// # Example:
    /// ```no_run
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    /// ```
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).write(true).open("/dev/sev")?,
        ))
    }

    /// Query the SNP platform status.
    ///
    /// # Example:
    /// ```no_run
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// let status: SnpPlatformStatus = firmware.snp_platform_status().unwrap();
    /// ```
    pub fn snp_platform_status(&mut self) -> Result<SnpPlatformStatus, Indeterminate<Error>> {
        let mut platform_status: SnpPlatformStatus = SnpPlatformStatus::default();
        SNP_PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::from_mut(&mut platform_status))?;
        Ok(platform_status)
    }

    /// Fetch the SNP Extended Configuration.
    ///
    /// # Example:
    /// ```no_run
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// let status: SnpExtConfig = firmware.snp_get_ext_config().unwrap();
    /// ```
    pub fn snp_get_ext_config(&mut self) -> Result<SnpExtConfig, UserApiError> {
        let mut raw_buf: Vec<u8> = vec![0; _4K_PAGE];
        let mut config: FFI::types::SnpGetExtConfig = FFI::types::SnpGetExtConfig {
            config_address: 0,
            certs_address: raw_buf.as_mut_ptr() as *mut CertTableEntry as u64,
            certs_len: _4K_PAGE as u32,
        };

        SNP_GET_EXT_CONFIG
            .ioctl(&mut self.0, &mut Command::from_mut(&mut config))
            .or_else(|err| {
                // If the error occurred because the buffer was to small, it will have changed
                // the buffer. If it has, we will attempt to resize it.
                if config.certs_len <= _4K_PAGE as u32 {
                    return Err(err);
                }

                raw_buf = vec![0; config.certs_len as usize];
                config.certs_address = raw_buf.as_ptr() as *const CertTableEntry as u64;
                SNP_GET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut config))
            })?;

        config.try_into().map_err(|op: uuid::Error| op.into())
    }

    /// Set the SNP Extended Configuration.
    ///
    /// # Example:
    /// ```no_run
    /// pub const ARK: &[u8] = include_bytes!("ark.pem");
    /// pub const ASK: &[u8] = include_bytes!("ask.pem");
    /// pub const VCEK: &[u8] = include_bytes!("vcek.pem");
    ///
    /// let configuration: SnpConfig = SnpConfig::new(
    ///     TcbVersion::new(3, 0, 10, 169),
    ///     0,
    /// );
    ///
    /// // Generate a vector of certificates to store in hypervisor memory.
    /// let certificates: Vec<CertTableEntry> = vec![
    ///     CertTableEntry::new(SnpCertType::ARK, ARK.to_vec()),
    ///     CertTableEntry::new(SnpCertType::ASK, ASK.to_vec()),
    ///     CertTableEntry::new(SnpCertType::VCEK, VCEK.to_vec()),
    /// ];
    ///
    /// // Call the `new` constructor to generate the extended configuration.
    /// let ext_config: SnpExtConfig = SnpExtConfig::new(configuration, certificates);
    ///
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// let status: bool = firmware.snp_set_ext_config(ext_config).unwrap();
    /// ```
    pub fn snp_set_ext_config(&mut self, new_config: SnpExtConfig) -> Result<bool, UserApiError> {
        let mut bytes: Vec<u8> = vec![];
        let mut new_ext_config: FFI::types::SnpSetExtConfig =
            FFI::types::SnpSetExtConfig::from_uapi(&new_config, &mut bytes)?;
        SNP_SET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut new_ext_config))?;
        Ok(true)
    }
}

impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
