// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Interfaces for a complete SEV-SNP certificate chain.

pub struct Chain {
    /// The Certificate Authority (CA) chain.
    pub ca: ca::Chain,

    /// The Versioned Chip Endorsement Key.
    pub vcek: Certificate,
}

impl<'a> Verifiable for &'a Chain {
    type Output = &'a Certificate;

    fn verify(self) -> Result<Self::Output> {
        // Verify that ARK is self-signed and ARK signs ASK.
        let ask = self.ca.verify()?;

        // Verify that ASK signs VCEK.
        (ask, &self.vcek).verify()?;

        Ok(&self.vcek)
    }
}
