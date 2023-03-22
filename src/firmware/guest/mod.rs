// SPDX-License-Identifier: Apache-2.0

//! # Guest Owner
//!
//! The Guest owner is a tenant of a virtualization provider. They may have
//! one or more guest confidential virtual-machines (VM) or containers which
//! may be deployed in a Platform Owner's environment..
//!
//! ## System Requirements:
//!
//! Guest-level support has been completed, and is upstream. In order to
//! access the guest driver, use Linux Kernel 5.19 or newer.
//!
//! ## API Capabilities:
//!
//! The Guest Owner is offered the following capabilities:
//!
//! -   Request a Standard Attestation report
//!
//! -   Request an Extended Attestation Report
//!
//! -   Request a unique key cryptographically derived from a hardware-owned
//!     secret.
//!
//! Although not within the scope of this library, possible attestation
//! practices have been included.
//!
//! ### Requesting and Attesting a Standard Attestation Report:
//!
//! 1.  Import the necessary pieces from the crate
//!
//!     ```no_run
//!     // Import the modules
//!     use sev::firmware::{
//!             guest::{
//!                 types::*,
//!                 Firmware,
//!             },
//!             host::types::*
//!     };
//!     ```
//!
//! 2.  Create and supply 64 bytes of unique data to include in the
//!     attestation report
//!
//!     ```no_run
//!     // This could be a unique message, a public key, etc.
//!     let unique_data: [u8; 64] = [
//!         65, 77, 68, 32, 105, 115, 32, 101, 120, 116, 114, 101, 109, 101, 108, 121, 32, 97, 119,
//!         101, 115, 111, 109, 101, 33, 32, 87, 101, 32, 109, 97, 107, 101, 32, 116, 104, 101, 32,
//!         98, 101, 115, 116, 32, 67, 80, 85, 115, 33, 32, 65, 77, 68, 32, 82, 111, 99, 107, 115,
//!         33, 33, 33, 33, 33, 33,
//!     ];
//!     ```
//!
//! 3.  Request the Report:
//!
//!     1.  Construct a
//!         [`SnpReportReq`](crate::firmware::linux::guest::types::SnpReportReq)
//!         from the unique data provided.
//!
//!         ```no_run
//!         // Specify the VMPL desired. This example will use zero.
//!         let request: SnpReportReq = SnpReportReq::new(Some(unique_data), 0);
//!         ```
//!
//!     2.  Connect to the firmware and request an attestation report
//!
//!         ```no_run
//!         // Open a connection to the firmware.
//!         let mut fw: Firmware = Firmware::open()?;
//!
//!         // Request a standard attestation report.
//!         let attestation_report: AttestationReport = fw.snp_get_report(None, request);
//!         ```
//!
//! 4.  Validate the Root of Trust:  \
//!      \
//!     One of the most significant steps in the attestation process is
//!     authenticating the root of trust. The
//!     [openssl](<https://crates.io/crates/openssl>) crate provides all of
//!     the needed tools to verify the signature chain. AMD's current root
//!     of trust is as follows:
//!
//!     1.  The AMD Root Key (ARK) is self-signed.
//!
//!     2.  The ARK signed the AMD Signing Key (ASK).
//!
//!     3.  The ASK signed the **V**ersioned **C**hip **E**ndorsement
//!         **K**ey (**VCEK**), or the **V**ersioned **L**oaded
//!         **E**ndorsement **K**ey (**VLEK**).
//!
//!     Following is an example of how this may be done:
//!
//!     1.  Import the necessary pieces from the
//!         `openssl` crate.
//!
//!         ```no_run
//!         use openssl::{
//!             ec::EcKey,
//!             ecdsa::EcdsaSig,
//!             pkey::{PKey, Public},
//!             sha::Sha384,
//!             x509::X509,
//!         };
//!         ```
//!
//!     2.  Pull the certificate chain from the AMD Key Distribution Server
//!         (KDS). Details for requesting the certificates may be found in
//!         the [VCEK
//!         Specification](https://www.amd.com/system/files/TechDocs/57230.pdf#page=15).
//!         Please note that all fields are expected to be a minimum of two
//!         characters in length, as well as zero-padded (ex. 8 => 08). You
//!         will find the `hwid` matches the `chip_id` on the attestation report.
//!
//!         ```no_run
//!         const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
//!         const KDS_VCEK: &str = "/vcek/v1";
//!         const KDS_CERT_CHAIN: &str = "cert_chain";
//!
//!         /// Requests the Certificate Chain (AMD ASK + AMD ARK)
//!         /// These may be used to verify the downloaded VCEK is authentic.
//!         pub fn request_cert_chain(sev_prod_name: &str) -> (ask, ark) {
//!             // Should make -> https://kdsintf.amd.com/vcek/v1/{SEV_PROD_NAME}/cert_chain
//!             let url: String = format!("{KDS_CERT_SITE}{KDS_VCEK}/{sev_prod_name}/{KDS_CERT_CHAIN}");
//!
//!             println!("Requesting AMD certificate chain from: {url}");
//!
//!             let rsp: Response = get(&url).unwrap();
//!
//!             let body: Vec<u8> = rsp.bytes().unwrap().to_vec();
//!
//!             let chain: Vec<X509> = X509::stack_from_pem(&body).unwrap();
//!
//!             (chain[0], chain[1])
//!         }
//!
//!         /// Requests the VCEK for the specified chip and TCP
//!         pub fn request_vcek(chip_id: [u8; 64], reported_tcb: TcbVersion) -> X509 {
//!             let hw_id: String = hexify(&chip_id);
//!             let url: String = format!(
//!             "{KDS_CERT_SITE}{KDS_VCEK}/{SEV_PROD_NAME}/\
//!             {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
//!             reported_tcb.boot_loader,
//!             reported_tcb.tee,
//!             reported_tcb.snp,
//!             reported_tcb.microcode
//!             );
//!
//!             println!("Requesting VCEK from: {url}\n");
//!
//!             let rsp_bytes = get(&url).unwrap().bytes().unwrap().to_vec();
//!
//!             X509::from_der(&rsp_bytes).unwrap()
//!         }
//!         ```
//!
//!     3.  Verify the Root of Trust
//!
//!         ```no_run
//!         let (ask, ark): (X509, X509) = request_cert_chain("milan");
//!
//!         // chip_id and reported_tcb should be pulled from the host machine,
//!         // or an attestation report.
//!         let vcek: X509 = request_vcek(
//!             chip_id,
//!             reported_tcb
//!         );
//!
//!         let ark_pubkey: PKey<Public> = ark.public_key().unwrap();
//!         let ask_pubkey: PKey<Public> = ask.public_key().unwrap();
//!
//!         if ark.verify(&ark_pubkey).unwrap() {
//!             println!("The AMD ARK was self-signed...");
//!             if ask.verify(&ark_pubkey).unwrap() {
//!                 println!("The AMD ASK was signed by the AMD ARK...");
//!                 if vcek.verify(&ask_pubkey).unwrap() {
//!                     println!("The VCEK was signed by the AMD ASK...");
//!                 } else {
//!                     eprintln!("The VCEK was not signed by the AMD ASK!");
//!                 }
//!             } else {
//!                 eprintln!("The AMD ASK was not signed by the AMD ARK!");
//!             }
//!         } else {
//!             eprintln!("The AMD ARK is not self-signed!");
//!         }
//!         ```
//!
//! 5.  Verify the Trusted Compute Base of the Guest:  \
//!      \
//!     The Following fields should be verified in an Attestation Report and
//!     a VCEK or VLEK:
//!
//!     -   Bootloader
//!
//!     -   TEE
//!
//!     -   SNP
//!
//!     -   Microcode
//!
//!     -   Chip ID
//!
//!     Unfortunately, the `openssl` crate does
//!     not support validating X509v3 Extensions (at time of writing). One
//!     possible solution is to use the
//!     [x509_parser](https://docs.rs/x509-parser/0.14.0/x509_parser/)
//!     crate, in conjunction with the
//!     [asn1_rs](https://docs.rs/asn1-rs/latest/asn1_rs/index.html) crate
//!     (for OIDs). The following examples will be built off of these
//!     definitions:
//!
//!     ```no_run
//!     /***********************************************************************************************
//!      *                               RELEVANT X509v3 EXTENSION OIDS
//!      ***********************************************************************************************/
//!     use asn1_rs::{oid, Oid};
//!     use x509_parser::{
//!         self,
//!         certificate::X509Certificate,
//!         pem::{parse_x509_pem, Pem},
//!         prelude::X509Extension,
//!     };
//!
//!     enum SnpOid {
//!         BootLoader,
//!         Tee,
//!         Snp,
//!         Ucode,
//!         HwId,
//!     }
//!
//!     impl SnpOid {
//!         fn oid(&self) -> Oid {
//!             match self {
//!                 SnpOid::BootLoader => oid!(1.3.6.1.4.1.3704.1.3.1),
//!                 SnpOid::Tee => oid!(1.3.6.1.4.1.3704.1.3.2),
//!                 SnpOid::Snp => oid!(1.3.6.1.4.1.3704.1.3.3),
//!                 SnpOid::Ucode => oid!(1.3.6.1.4.1.3704.1.3.8),
//!                 SnpOid::HwId => oid!(1.3.6.1.4.1.3704.1.4),
//!             }
//!         }
//!     }
//!
//!     impl std::fmt::Display for SnpOid {
//!         fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!             write!(f, "{}", self.oid().to_id_string())
//!         }
//!     }
//!
//!
//!     /***********************************************************************************************
//!      *                                       HELPER FUNCTIONS
//!      ***********************************************************************************************/
//!
//!
//!     fn check_cert_ext_byte(ext: &X509Extension, val: u8) -> bool {
//!         if ext.value[0] != 0x2 {
//!             panic!("Invalid type encountered!");
//!         }
//!
//!         if ext.value[1] != 0x1 && ext.value[1] != 0x2 {
//!             panic!("Invalid octet length encountered");
//!         }
//!
//!         if let Some(byte_value) = ext.value.last() {
//!             *byte_value == val
//!         } else {
//!             false
//!         }
//!     }
//!
//!     fn check_cert_ext_bytes(ext: &X509Extension, val: &[u8]) -> bool {
//!         ext.value == val
//!     }
//!
//!
//!     /************************************************************************************************
//!      *                                  EXAMPLE ATTESTATION FUNCTION:
//!      ***********************************************************************************************/
//!
//!     fn validate_cert_metadata(
//!         cert: &X509Certificate,
//!         report: &AttestationReport,
//!     ) -> bool {
//!         let extensions: HashMap<Oid, &X509Extension> = cert.extensions_map().unwrap();
//!
//!         if let Some(cert_bl) = extensions.get(&SnpOid::BootLoader.oid()) {
//!             if !check_cert_ext_byte(cert_bl, report.reported_tcb.boot_loader) {
//!                 eprintln!("Report TCB Boot Loader and Certificate Boot Loader mismatch encountered.");
//!                 return false;
//!             }
//!             println!("Reported TCB Boot Loader from certificate matches the attestation report.");
//!         }
//!
//!         if let Some(cert_tee) = extensions.get(&SnpOid::Tee.oid()) {
//!             if !check_cert_ext_byte(cert_tee, report.reported_tcb.tee) {
//!                 eprintln!("Report TCB TEE and Certificate TEE mismatch encountered.");
//!                 return false;
//!             }
//!             println!("Reported TCB TEE from certificate matches the attestation report.");
//!         }
//!
//!         if let Some(cert_snp) = extensions.get(&SnpOid::Snp.oid()) {
//!             if !check_cert_ext_byte(cert_snp, report.reported_tcb.snp) {
//!                 eprintln!("Report TCB SNP and Certificate SNP mismatch encountered.");
//!                 return false;
//!             }
//!             println!("Reported TCB SNP from certificate matches the attestation report.");
//!         }
//!
//!         if let Some(cert_ucode) = extensions.get(&SnpOid::Ucode.oid()) {
//!             if !check_cert_ext_byte(cert_ucode, report.reported_tcb.microcode) {
//!                 eprintln!("Report TCB Microcode and Certificate Microcode mismatch encountered.");
//!                 return false;
//!             }
//!             println!("Reported TCB Microcode from certificate matches the attestation report.");
//!         }
//!
//!         if let Some(cert_hwid) = extensions.get(&SnpOid::HwId.oid()) {
//!             if !check_cert_ext_bytes(cert_hwid, &report.chip_id) {
//!                 eprintln!("Report TCB Microcode and Certificate Microcode mismatch encountered.");
//!                 return false;
//!             }
//!             println!("Chip ID from certificate matches the attestation report.");
//!         }
//!
//!         true
//!     }
//!     ```
//!
//! 6.  Verify Attestation Report Signature by VCEK/VLEK \
//!      \
//!     The last step is to verify the signature contained on the
//!     Attestation Report truly came from the VCEK/VLEK. \
//!
//!     ```no_run
//!     let ar_signature: EcdsaSig = EcdsaSig::try_from(&report.signature).unwrap();
//!     let signed_bytes: &[u8] = &bincode::serialize(&report).unwrap()[0x0..0x2A0];
//!
//!     let vcek_pubkey: EcKey<Public> = vcek.public_key().unwrap().ec_key().unwrap();
//!
//!     let mut hasher: Sha384 = Sha384::new();
//!     hasher.update(signed_bytes);
//!     let base_message_digest: [u8; 48] = hasher.finish();
//!
//!     if ar_signature.verify(base_message_digest.as_ref(), amd_vcek_pubkey.as_ref()).unwrap() {
//!         println!("VCEK signed the Attestation Report!");
//!     } else {
//!         eprintln!("VCEK did NOT sign the Attestation Report!");
//!     }
//!     ```
//!
//! ### Requesting and Attesting an Extended Attestation Report:
//!
//! 1.  Create and supply 64 bytes of unique data to include in the
//!     attestation report
//!
//!     ```no_run
//!     // This could be a unique message, a public key, etc.
//!     let unique_data: [u8; 64] = [
//!         65, 77, 68, 32, 105, 115, 32, 101, 120, 116, 114, 101, 109, 101, 108, 121, 32, 97, 119,
//!         101, 115, 111, 109, 101, 33, 32, 87, 101, 32, 109, 97, 107, 101, 32, 116, 104, 101, 32,
//!         98, 101, 115, 116, 32, 67, 80, 85, 115, 33, 32, 65, 77, 68, 32, 82, 111, 99, 107, 115,
//!         33, 33, 33, 33, 33, 33,
//!     ];
//!     ```
//!
//! 2.  Construct a
//!     `SnpReportReq` from
//!     the unique data provided.
//!
//!     ```no_run
//!     // Specify the VMPL desired. This example will use zero.
//!     let request: SnpReportReq = SnpReportReq::new(Some(unique_data), 0);
//!     ```
//!
//! 3.  Connect to the Firmware and Request the Extended Report
//!
//!     ```no_run
//!     let mut fw: Firmware = Firmware::open().unwrap();
//!
//!     let (extended_report, certificates): (AttestationReport, Vec<CertTableEntry>) = fw.snp_get_ext_report(None, request)
//!     ```
//!
//! 4.  Verify the Root of Trust:
//!
//!     1.  Parse the ARK, ASK, and VCEK obtained from the AMD Secure
//!         Processor:
//!
//!         ```no_run
//!         // Assuming we have created a structure called AMDCerts, like this:
//!         #[(Clone, Debug, Default)]
//!         struct AMDCerts {
//!             pub ask: Option<X509>,
//!             pub ark: Option<X509>,
//!             pub vcek: Option<X509>,
//!         }
//!
//!
//!         // Assumes all certificates are in PEM format (for simplicity).
//!         fn parse_certificates(certificates: &[CertTableEntry]) -> AMDCerts {
//!             let mut certs: AMDCerts = Default::default();
//!
//!             for cert in certificates.iter() {
//!                 let parsed_cert: Option<X509> = Some(X509::from_pem(cert.data()).unwrap());
//!
//!                 match cert.cert_type {
//!                     SnpCertType::ARK => certs.ark = parsed_cert,
//!                     SnpCertType::ASK => certs.ask = parsed_cert,
//!                     SnpCertType::VCEK => certs.vcek = parsed_cert,
//!                     _ => (),
//!                 }
//!             }
//!
//!             certs
//!         }
//!         ```
//!
//!     2.  Proceed with Standard Attestation Report Root of Trust
//!         Verification, skipping the HTTP requests to the AMD Key
//!         Distribution Server.
//!
//! ### Requesting a Derived Key:
//!
//! There are many use-cases when a Guest Owner may wish to generate a
//! unique encryption key which has been derived from the Hardware Root of
//! Trust. The guest can request that the key derivation be made dependent
//! on several TCB related parameters which allow the guest to rederive the
//! key only when the same parameter(s) are provided..
//!
//! 1.  Construct a
//!     `SnpDerivedKey` as
//!     per the specification:
//!
//!     ```no_run
//!     let request: SnpDerivedKey = SnpDerivedKey::new(false, GuestFieldSelect(1), 0, 0, 0);
//!     ```
//!
//! 2.  Connect to the Firmware and request a derived key:
//!
//!     ```no_run
//!     let mut fw: Firmware = Firmware::open().unwrap();
//!
//!     let derived_key: SnpDerivedKeyRsp = fw.snp_get_derived_key(None, request).unwrap();
//!     ```
//!

pub mod types;

use std::fs::{File, OpenOptions};

use super::host::types::CertTableEntry;
use crate::error::*;
use types::*;
use GuestFFI::ioctl::*;
use GuestFFI::types::*;

// Disabled until upstream Linux kernel is patched.
//
// /// Checks the `fw_err` field on the [`SnpGuestRequest`] structure
// /// to make sure that no errors were encountered by the VMM or the AMD
// /// Secure Processor.
// fn check_fw_err(raw_error: RawFwError) -> Result<(), UserApiError> {
//     if raw_error != 0.into() {
//         let (upper, lower): (u32, u32) = raw_error.into();
//
//         if upper != 0 {
//             return Err(VmmError::from(upper).into());
//         }
//
//         if lower != 0 {
//             match lower.into() {
//                 Indeterminate::Known(error) => return Err(error.into()),
//                 Indeterminate::Unknown => return Err(UserApiError::Unknown),
//             }
//         }
//     }
//     Ok(())
// }

/// A handle to the SEV, SEV-ES, or SEV-SNP platform.
pub struct Firmware(File);

impl Firmware {
    /// Generate a new file handle to the SEV guest platform via `/dev/sev-guest`.
    ///
    /// # Example:
    ///
    /// ```no_run
    /// let mut firmware: Firmware = firmware.open().unwrap();
    /// ```
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/sev-guest")?,
        ))
    }

    /// Requests an attestation report from the AMD Secure Processor. The `message_version` will default to `1` if `None` is specified.
    ///
    /// # Example:
    ///
    /// ```no_run
    /// // Create some unique data we wish to see included in our report. This could be a SHA, a public key, etc.
    /// let unique_data: [u8; 64] = [
    ///     65, 77, 68, 32, 105, 115, 32, 101, 120, 116, 114, 101, 109, 101, 108, 121, 32, 97, 119,
    ///     101, 115, 111, 109, 101, 33, 32, 87, 101, 32, 109, 97, 107, 101, 32, 116, 104, 101, 32,
    ///     98, 101, 115, 116, 32, 67, 80, 85, 115, 33, 32, 65, 77, 68, 32, 82, 111, 99, 107, 115,
    ///     33, 33, 33, 33, 33, 33,
    /// ];
    ///
    /// // Create a message version (OPTIONAL)
    /// let msg_ver: u8 = 1;
    ///
    /// // Open a connection to the AMD Secure Processor.
    /// let mut fw: Firmware = Firmware::open().unwrap();
    ///
    /// // Request the attestation report with our unique_data.
    /// let attestation_report: AttestationReport = fw.snp_get_report(msg_ver, unique_data).unwrap();
    /// ```
    pub fn snp_get_report(
        &mut self,
        message_version: Option<u8>,
        mut report_request: SnpReportReq,
    ) -> Result<AttestationReport, UserApiError> {
        let mut report_response: SnpReportRsp = Default::default();

        let mut request: SnpGuestRequest<SnpReportReq, SnpReportRsp> =
            SnpGuestRequest::new(message_version, &mut report_request, &mut report_response);

        SNP_GET_REPORT.ioctl(&mut self.0, &mut request)?;

        // Disabled until upstream Linux kernel is patched.
        // check_fw_err(request.fw_err.into())?;

        Ok(report_response.report)
    }

    /// Request an extended attestation report from the AMD Secure Processor. The `message_version` will default to `1` if `None` is specified. Behaves the same as [`snp_get_report`](crate::firmware::guest::Firmware::snp_get_report).
    pub fn snp_get_ext_report(
        &mut self,
        message_version: Option<u8>,
        mut report_request: SnpReportReq,
    ) -> Result<(AttestationReport, Vec<CertTableEntry>), UserApiError> {
        let mut report_response: SnpReportRsp = Default::default();

        // Define a buffer to store the certificates in.
        let mut certificate_bytes: Vec<u8>;

        // Due to the complex buffer allocation, we will take the SnpReportReq
        // provided by the caller, and create an extended report request object
        // for them.
        let mut ext_report_request: SnpExtReportReq = SnpExtReportReq::new(&mut report_request);

        // Construct the object needed to perform the IOCTL request.
        // *NOTE:* This is __important__ because a fw_err value which matches
        // [`INVALID_CERT_BUFFER`] will indicate the buffer was not large
        // enough.
        let mut guest_request: SnpGuestRequest<SnpExtReportReq, SnpReportRsp> =
            SnpGuestRequest::new(
                message_version,
                &mut ext_report_request,
                &mut report_response,
            );

        // KEEP for Kernels before 47894e0f (5.19), as userspace broke at that hash.
        if let Err(ioctl_error) = SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request) {
            match guest_request.fw_err.into() {
                VmmError::InvalidCertificatePageLength => (),
                VmmError::RateLimitRetryRequest => {
                    return Err(VmmError::RateLimitRetryRequest.into())
                }
                _ => return Err(ioctl_error.into()),
            }

            // Eventually the code below will be moved back into this scope.
        }

        // The kernel patch by pgonda@google.com in kernel hash 47894e0f
        // changed the ioctl return to succeed instead of returning an
        // error when encountering an invalid certificate length. This was
        // done to keep the cryptography safe, so we will now just check
        // the guest_request.fw_err for a new value.
        //
        // Check to see if the buffer needs to be resized. If it does, the
        // we need to resize the buffer to the correct size, and
        // re-request for the certificates.
        if VmmError::InvalidCertificatePageLength == guest_request.fw_err.into() {
            certificate_bytes = vec![0u8; ext_report_request.certs_len as usize];
            ext_report_request.certs_address = certificate_bytes.as_mut_ptr() as u64;
            let mut guest_request_retry: SnpGuestRequest<SnpExtReportReq, SnpReportRsp> =
                SnpGuestRequest::new(
                    message_version,
                    &mut ext_report_request,
                    &mut report_response,
                );
            SNP_GET_EXT_REPORT.ioctl(&mut self.0, &mut guest_request_retry)?;
        } else if guest_request.fw_err != 0 {
            // This shouldn't be possible, but if it happens, throw an error.
            return Err(UserApiError::FirmwareError(Error::InvalidConfig));
        }

        let certificates: Vec<CertTableEntry>;

        unsafe {
            let entries = (ext_report_request.certs_address as *mut HostFFI::types::CertTableEntry)
                .as_mut()
                .ok_or(SnpCertError::EmptyCertBuffer)?;
            certificates = HostFFI::types::CertTableEntry::parse_table(entries)?;
        }

        // Return both the Attestation Report, as well as the Cert Table.
        Ok((report_response.report, certificates))
    }


    /// Fetches a derived key from the AMD Secure Processor. The `message_version` will default to `1` if `None` is specified.
    ///
    /// # Example:
    /// ```no_run
    /// let request: SnpDerivedKey = SnpDerivedKey::new(false, GuestFieldSelect(1), 0, 0, 0);
    ///
    /// let mut fw: Firmware = Firmware::open().unwrap();
    /// let derived_key: SnpDerivedKeyRsp = fw.snp_get_derived_key(None, request).unwrap();
    /// ```
    pub fn snp_get_derived_key(
        &mut self,
        message_version: Option<u8>,
        derived_key_request: SnpDerivedKey,
    ) -> Result<[u8; 32], UserApiError> {
        let mut ffi_derived_key_request: SnpDerivedKeyReq = derived_key_request.into();
        let mut ffi_derived_key_response: SnpDerivedKeyRsp = Default::default();

        let mut request: SnpGuestRequest<SnpDerivedKeyReq, SnpDerivedKeyRsp> = SnpGuestRequest::new(
            message_version,
            &mut ffi_derived_key_request,
            &mut ffi_derived_key_response,
        );

        SNP_GET_DERIVED_KEY.ioctl(&mut self.0, &mut request)?;

        // Disabled until upstream Linux kernel is patched.
        // check_fw_err(request.fw_err.into())?;

        Ok(ffi_derived_key_response.key)
    }
}
