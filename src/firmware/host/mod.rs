// SPDX-License-Identifier: Apache-2.0

//! # Host / Platform Owner
//!
//! The Platform Owner, Host, or Cloud Service Provider (CSP). This is the system software, including the hypervisor, where a confidential virtual-machine (VM) or container will be deployed.
//!
//!
//! ## System Requirements:
//!
//!
//! ### Kernel Requirements:
//!
//! Development for SEV-SNP is on-going. Until it is upstream, it is recommended to use a branch from the AMD fork of the Linux kernel. At the time of writing, this is [sev-snp-iommu-avic_5.19-rc6_v4](https://github.com/AMDESE/linux/tree/sev-snp-iommu-avic_5.19-rc6_v4).
//!
//!
//! ### Hardware / Firmware Requirements:
//!
//!
//! The [snp](https://github.com/virtee/snp) crate is compatible with firmware ([version 1.54.01](https://download.amd.com/developer/eula/sev/amd_sev_fam19h_model0xh_1.54.01.zip)).
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
//! ## API Capabilities:
//!
//! Platform owners are offered the following capabilities:
//!
//! -   Request the Status of the AMD Secure Processor.
//!
//! -   Load New Extended Configurations
//!
//! -   Request Existing Extended Configurations
//!
//! By deciding to store policies and certificate-chains in hypervisor
//! memory, the platform owner promotes greater guest owner ease-of-use.
//! Further, it reduces the dependency of CSP operations on AMD's Key
//! Distribution Server (KDS).
//!
//! ### Request the Status of the AMD Secure Processor:
//!
//! 1.  Include the `snp`
//!     crate into your Rust project.
//!
//!     ```no_run
//!     // Import library
//!     use snp::firmware::host::types::*;
//!     ```
//!
//! 2.  Connect to the firmware and request for the status of the AMD Secure
//!     Processor:
//!
//!     ```no_run
//!     // Open a connection to the firmware.
//!     let mut firmware: Firmware = Firmware::open().unwrap();
//!
//!     // Request the current status of the AMD Secure Processor.
//!     let status: SnpPlatformStatus = firmware.snp_platform_status().unwrap();
//!     ```
//!
//! ### Load New Extended Configurations:
//!
//! 1.  Include the `snp`
//!     crate into your Rust project.
//!
//!     ```no_run
//!     // Import library
//!     use snp::firmware::host::types::*;
//!     ```
//!
//! 2.  Read the bytes of the certificates which will be stored in
//!     Hypervisor memory. This could be done with
//!     `include_bytes!()`,
//!     or by some other means. This example will use
//!     `include_bytes!()`.
//!
//!     ```no_run
//!     // Read certificate bytes.
//!     pub const ARK: &[u8] = include_bytes!("ark.pem");
//!     pub const ASK: &[u8] = include_bytes!("ask.pem");
//!     pub const VCEK: &[u8] = include_bytes!("vcek.pem");
//!     ```
//!
//! 3.  Create a configuration for when guests request an extended report
//!     (**choose one**):
//!
//!     -   **OPTION A**: Certificates Only
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
//!         let ext_config: SnpExtConfig = SnpExtConfig::update_certs_only(
//!             certificates
//!         );
//!         ```
//!
//!     -   **OPTION B**: Configuration Only
//!
//!         ```no_run
//!         // Specify the desired configuration
//!         let configuration: SnpConfig = SnpConfig::new(
//!             TcbVersion::new(3, 0, 10, 169),
//!             0,
//!         );
//!
//!         // Call the `update_config_only` constructor to generate the extended configuration.
//!         let ext_config: SnpExtConfig = SnpExtConfig::update_config_only(
//!             configuration
//!         );
//!         ```
//!
//!     -   **OPTION C**: Configuration and Certificates
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
//!         let ext_config: SnpExtConfig = SnpExtConfig::new(
//!             configuration,
//!             certificates
//!         );
//!         ```
//!
//! 4.  Connect to the firmware and forward the extended request to the AMD
//!     Secure Processor:
//!
//!     ```no_run
//!     // Open a connection to the firmware.
//!     let mut fw: Firmware = Firmware::open().unwrap();
//!
//!     // Forward the certificates to the AMD Secure Processor to be loaded.
//!     if let Err(error) = fw.snp_set_ext_config(&ext_config) {
//!         // Handle an error if one is encountered.
//!         ...
//!     }
//!     ```
//!
//! ### Request Existing Extended Configurations:
//!
//! 1.  Include the `snp`
//!     crate into your Rust project.
//!
//!     ```no_run
//!     // Import library
//!     use snp::firmware::host::types::*;
//!     ```
//!
//! 2.  Connect to the firmware and request for the current configuration:
//!
//!     ```no_run
//!     // Open a connection to the firmware.
//!     let mut fw: Firmware = Firmware::open().unwrap();
//!
//!     // Request the current configuration.
//!     let current_configuration: SnpExtConfig = fw.snp_get_ext_config().unwrap();
//!     ```

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
