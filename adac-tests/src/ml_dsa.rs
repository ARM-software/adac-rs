// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(test)]
mod tests {
    use crate::{run_test_with, TestSettings};
    use adac::{
        certificate::AdacCertificate,
        traits::{AdacCryptoProvider, AdacKeyFormat},
        AdacVersion, KeyOptions,
    };
    use adac::{CertificateHeader, CertificateRole::*, KeyOptions::*};
    use adac_crypto::utils::*;

    #[test]
    fn aws_lc_ml_dsa_44() {
        run_test_with(&TestSettings::default(), || {
            aws_lc_ml_dsa_test(
                MlDsa44Sha256,
                vec![
                    "resources/keys/MlDsa44Key-0.pk8",
                    "resources/keys/MlDsa44Key-1.pk8",
                    "resources/keys/MlDsa44Key-2.pk8",
                    "resources/keys/MlDsa44Key-3.pk8",
                ],
            )
        });
    }

    #[test]
    fn aws_lc_ml_dsa_65() {
        run_test_with(&TestSettings::default(), || {
            aws_lc_ml_dsa_test(
                MlDsa65Sha384,
                vec![
                    "resources/keys/MlDsa65Key-0.pk8",
                    "resources/keys/MlDsa65Key-1.pk8",
                    "resources/keys/MlDsa65Key-2.pk8",
                    "resources/keys/MlDsa65Key-3.pk8",
                ],
            )
        });
    }

    #[test]
    fn aws_lc_ml_dsa_87() {
        run_test_with(&TestSettings::default(), || {
            aws_lc_ml_dsa_test(
                MlDsa87Sha512,
                vec![
                    "resources/keys/MlDsa87Key-0.pk8",
                    "resources/keys/MlDsa87Key-1.pk8",
                    "resources/keys/MlDsa87Key-2.pk8",
                    "resources/keys/MlDsa87Key-3.pk8",
                ],
            )
        });
    }

    fn aws_lc_ml_dsa_test(key_type: KeyOptions, key_paths: Vec<&str>) {
        let mut crypto = adac_crypto_aws_lc::AwsLcCryptoProvider::default();
        let keys: Vec<Vec<u8>> = key_paths.iter().map(|p| load_key(p).unwrap().1).collect();

        let mut h = CertificateHeader {
            format_version: AdacVersion { major: 1, minor: 1 },
            role: AdacCrtRoleRoot,
            permissions_mask: [0xFFu8; 16],
            key_type,
            signature_type: key_type,
            usage: adac::CertificateUsage::AdacUsageStandard,
            ..Default::default()
        };

        let mut chain = vec![];
        let mut export = vec![];
        let mut key = &keys[0];
        for (i, current) in keys.iter().enumerate() {
            crypto
                .load_key(key_type, AdacKeyFormat::Pkcs8, key.clone().as_slice())
                .unwrap();
            let public_key = get_public_key(key_type, current).unwrap();

            if i > 0 {
                h.role = if i < keys.len() - 1 {
                    AdacCrtRoleInt
                } else {
                    AdacCrtRoleLeaf
                }
            }

            let certificate =
                AdacCertificate::sign(key_type, h, public_key.as_slice(), None, &mut crypto)
                    .unwrap();
            export.extend_from_slice(adac::tlv_wrap(0x201, certificate.to_bytes()).as_slice());
            chain.push(certificate);
            key = current;
        }

        // println!("{}", save_certificates(&chain).unwrap());

        verify_chain(chain, &crypto).unwrap();
    }
}
