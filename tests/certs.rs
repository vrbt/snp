// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "openssl")]
use snp::certs::{builtin::milan, ca, Certificate, Chain, Verifiable};

#[cfg(feature = "openssl")]
const TEST_MILAN_VCEK_DER: &[u8] = include_bytes!("certs_data/vcek_milan.der");

#[cfg(feature = "openssl")]
const TEST_MILAN_ATTESTATION_REPORT: &[u8] = include_bytes!("certs_data/report_milan.hex");

#[cfg(feature = "openssl")]
#[test]
fn milan_chain() {
    let ark = milan::ark().unwrap();
    let ask = milan::ask().unwrap();
    let vcek = Certificate::from_der(TEST_MILAN_VCEK_DER).unwrap();

    let ca = ca::Chain { ark, ask };

    let chain = Chain { ca, vcek };

    chain.verify().unwrap();
}

#[cfg(feature = "openssl")]
#[test]
fn milan_report() {
    use snp::firmware::guest::AttestationReport;

    let ark = milan::ark().unwrap();
    let ask = milan::ask().unwrap();
    let vcek = Certificate::from_der(TEST_MILAN_VCEK_DER).unwrap();

    let ca = ca::Chain { ark, ask };

    let chain = Chain { ca, vcek };

    let report_bytes = hex::decode(TEST_MILAN_ATTESTATION_REPORT).unwrap();
    let report: AttestationReport = unsafe { std::ptr::read(report_bytes.as_ptr() as *const _) };

    (&chain, &report).verify().unwrap();
}
