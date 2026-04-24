// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(test)]
mod tests {
    use adac::KeyOptions;
    use adac::KeyOptions::*;
    use adac::certificate::AdacCertificate;
    use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
    use adac_crypto::utils::*;

    #[test]
    fn ecdsa_p256_chain() {
        let crypto = adac_crypto_aws_lc::AwsLcCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.EcdsaP256").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ecdsa_p384_chain() {
        let crypto = adac_crypto_aws_lc::AwsLcCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.EcdsaP384").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ecdsa_p521_chain() {
        let crypto = adac_crypto_aws_lc::AwsLcCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.EcdsaP521").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ml_dsa_44_chain() {
        let crypto = adac_crypto_aws_lc::AwsLcCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.MlDsa44").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ml_dsa_65_chain() {
        let crypto = adac_crypto_aws_lc::AwsLcCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.MlDsa65").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ml_dsa_87_chain() {
        let crypto = adac_crypto_aws_lc::AwsLcCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.MlDsa87").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ml_dsa_65_chain_rejects_nonzero_signature_padding() {
        let crypto = adac_crypto_aws_lc::AwsLcCryptoProvider::default();
        let mut chain = load_certificates("resources/chains/chain.MlDsa65").unwrap();
        let certificate = chain.pop().unwrap();
        let mut bytes = certificate.to_bytes();
        let signature_offset = certificate.get_tbs().len();
        bytes[signature_offset + adac::MLDSA_65_SIGNATURE_UNPADDED] ^= 0x01;
        let certificate = AdacCertificate::from_bytes(bytes).unwrap();

        assert!(
            certificate
                .verify(chain.last().unwrap().get_public_key(), &crypto)
                .is_err()
        );
    }

    #[test]
    fn ecdsa_p256_chain_sig() {
        ecdsa_chain_sig_test(
            EcdsaP256Sha256,
            vec![
                "resources/keys/EcdsaP256Key-0.pk8",
                "resources/keys/EcdsaP256Key-1.pk8",
                "resources/keys/EcdsaP256Key-2.pk8",
                "resources/keys/EcdsaP256Key-3.pk8",
            ],
            None,
        )
    }

    #[test]
    fn ecdsa_p384_chain_sig() {
        ecdsa_chain_sig_test(
            EcdsaP384Sha384,
            vec![
                "resources/keys/EcdsaP384Key-0.pk8",
                "resources/keys/EcdsaP384Key-1.pk8",
                "resources/keys/EcdsaP384Key-2.pk8",
                "resources/keys/EcdsaP384Key-3.pk8",
            ],
            None,
        )
    }

    #[test]
    fn ecdsa_p521_chain_sig() {
        ecdsa_chain_sig_test(
            EcdsaP521Sha512,
            vec![
                "resources/keys/EcdsaP521Key-0.pk8",
                "resources/keys/EcdsaP521Key-1.pk8",
                "resources/keys/EcdsaP521Key-2.pk8",
                "resources/keys/EcdsaP521Key-3.pk8",
            ],
            None,
        )
    }

    fn ecdsa_chain_sig_test(key_type: KeyOptions, key_paths: Vec<&str>, test_file: Option<&str>) {
        let mut crypto = adac_crypto_aws_lc::AwsLcCryptoProvider::default();
        let keys: Vec<Vec<u8>> = key_paths.iter().map(|p| load_key(p).unwrap().1).collect();

        let mut chain = vec![];
        let mut export = vec![];
        let mut key = &keys[0];
        for (i, current) in keys.iter().enumerate() {
            crypto
                .load_key(key_type, AdacKeyFormat::Pkcs8, key.clone().as_slice())
                .unwrap();
            let public_key = get_public_key(key_type, current).unwrap();
            let h = crate::test_certificate_header(key_type, i);

            let certificate =
                AdacCertificate::sign(key_type, h, public_key.as_slice(), None, &mut crypto)
                    .unwrap();
            export.extend_from_slice(adac::tlv_wrap(0x201, certificate.to_bytes()).as_slice());
            chain.push(certificate);
            key = current;
        }

        // Compare certificates with chain from test file.
        // AwsLcCryptoProvider does not support deterministic ECDSA Signature.
        if let Some(test_file) = test_file {
            let reference = load_certificates(test_file).unwrap();
            assert_eq!(chain.len(), reference.len());
            // for i in 0..chain.len() {
            //     let c = chain[i].to_bytes();
            //     let r = reference[i].to_bytes();
            //     assert_eq!(c.len(), r.len());
            //     assert_eq!(c, r);
            // }
            verify_chain(reference, &crypto).unwrap();
        }

        verify_chain(chain, &crypto).unwrap();
    }
}
