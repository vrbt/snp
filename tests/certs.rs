// SPDX-License-Identifier: Apache-2.0

use snp::certs::{builtin::milan, ca, Certificate, Chain, Verifiable};

const TEST_MILAN_VCEK_DER: &[u8] = include_bytes!("certs_data/vcek_milan.der");

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
