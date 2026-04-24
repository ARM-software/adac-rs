// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(test)]
mod tests {
    use crate::{TestSettings, run_test_with};
    use adac::CertificateRole::{AdacCrtRoleInt, AdacCrtRoleLeaf, AdacCrtRoleRoot};
    use adac::CertificateUsage::AdacUsageRma;
    use adac::KeyOptions::*;
    use adac::certificate::AdacCertificate;
    use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
    use adac::{AdacVersion, CertificateHeader, KeyOptions};
    use adac_crypto::utils::{
        get_public_key, load_certificates, load_key, read_certificates, save_certificates,
        verify_chain,
    };
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn ecdsa_p256_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.EcdsaP256").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.EcdsaP256").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ecdsa_p384_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.EcdsaP384").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.EcdsaP384").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ecdsa_p521_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.EcdsaP521").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.EcdsaP521").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ed25519_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.Ed25519").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.Ed25519").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ed448_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.Ed448").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.Ed448").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ml_dsa_44_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.MlDsa44").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.MlDsa44").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ml_dsa_65_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.MlDsa65").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.MlDsa65").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ml_dsa_87_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.MlDsa87").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.MlDsa87").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn rsa_3072_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.Rsa3072").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.Rsa3072").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn rsa_4096_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.Rsa4096").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.Rsa4096").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn sm2_chain() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();

        let chain = load_certificates("resources/chains/chain.Sm2").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, &crypto).unwrap();

        let chain = load_certificates("resources/roots/root.Sm2").unwrap();
        assert_eq!(chain.len(), 1);
        verify_chain(chain, &crypto).unwrap();
    }

    #[test]
    fn ecdsa_p256_chain_sig() {
        rust_crypto_chain_sig_test(
            EcdsaP256Sha256,
            vec![
                "resources/keys/EcdsaP256Key-0.pk8",
                "resources/keys/EcdsaP256Key-1.pk8",
                "resources/keys/EcdsaP256Key-2.pk8",
                "resources/keys/EcdsaP256Key-3.pk8",
            ],
            Some("resources/chains/chain.EcdsaP256"),
        )
    }

    #[test]
    fn ecdsa_p256_root_sig() {
        rust_crypto_root_sig_test(
            EcdsaP256Sha256,
            "resources/keys/EcdsaP256Key-0.pk8",
            "resources/roots/root.EcdsaP256",
        )
    }

    #[test]
    fn ecdsa_p384_chain_sig() {
        rust_crypto_chain_sig_test(
            EcdsaP384Sha384,
            vec![
                "resources/keys/EcdsaP384Key-0.pk8",
                "resources/keys/EcdsaP384Key-1.pk8",
                "resources/keys/EcdsaP384Key-2.pk8",
                "resources/keys/EcdsaP384Key-3.pk8",
            ],
            Some("resources/chains/chain.EcdsaP384"),
        )
    }

    #[test]
    fn ecdsa_p384_root_sig() {
        rust_crypto_root_sig_test(
            EcdsaP384Sha384,
            "resources/keys/EcdsaP384Key-0.pk8",
            "resources/roots/root.EcdsaP384",
        )
    }

    #[ignore] // FIXME: NistP521 does not implement the DigestPrimitive trait.
    #[test]
    fn ecdsa_p521_chain_sig() {
        rust_crypto_chain_sig_test(
            EcdsaP521Sha512,
            vec![
                "resources/keys/EcdsaP521Key-0.pk8",
                "resources/keys/EcdsaP521Key-1.pk8",
                "resources/keys/EcdsaP521Key-2.pk8",
                "resources/keys/EcdsaP521Key-3.pk8",
            ],
            Some("resources/chains/chain.EcdsaP521"),
        )
    }

    #[ignore] // FIXME: NistP521 does not implement the DigestPrimitive trait.
    #[test]
    fn ecdsa_p521_root_sig() {
        rust_crypto_root_sig_test(
            EcdsaP521Sha512,
            "resources/keys/EcdsaP521Key-0.pk8",
            "resources/roots/root.EcdsaP521",
        )
    }

    #[test]
    fn ed25519_chain_sig() {
        rust_crypto_chain_sig_test(
            Ed25519Sha512,
            vec![
                "resources/keys/Ed25519Key-0.pk8",
                "resources/keys/Ed25519Key-1.pk8",
                "resources/keys/Ed25519Key-2.pk8",
                "resources/keys/Ed25519Key-3.pk8",
            ],
            Some("resources/chains/chain.Ed25519"),
        )
    }

    #[test]
    fn ed25519_root_sig() {
        rust_crypto_root_sig_test(
            Ed25519Sha512,
            "resources/keys/Ed25519Key-0.pk8",
            "resources/roots/root.Ed25519",
        )
    }

    #[test]
    fn ed448_chain_sig() {
        rust_crypto_chain_sig_test(
            Ed448Shake256,
            vec![
                "resources/keys/Ed448Key-0.pk8",
                "resources/keys/Ed448Key-1.pk8",
                "resources/keys/Ed448Key-2.pk8",
                "resources/keys/Ed448Key-3.pk8",
            ],
            Some("resources/chains/chain.Ed448"),
        )
    }

    #[test]
    fn ed448_root_sig() {
        rust_crypto_root_sig_test(
            Ed448Shake256,
            "resources/keys/Ed448Key-0.pk8",
            "resources/roots/root.Ed448",
        )
    }

    #[test]
    fn ed448_chain_rejects_nonzero_signature_padding() {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();
        let mut chain = load_certificates("resources/chains/chain.Ed448").unwrap();
        let certificate = chain.pop().unwrap();
        let mut bytes = certificate.to_bytes();
        let signature_offset = certificate.get_tbs().len();
        bytes[signature_offset + adac::ED448_SIGNATURE_SIZE_UNPADDED] ^= 0x01;
        let certificate = AdacCertificate::from_bytes(bytes).unwrap();

        assert!(
            certificate
                .verify(chain.last().unwrap().get_public_key(), &crypto)
                .is_err()
        );
    }

    #[test]
    fn ed448_chain_rejects_nonzero_public_key_padding() {
        let mut chain = load_certificates("resources/chains/chain.Ed448").unwrap();
        let certificate = chain.pop().unwrap();
        let mut bytes = certificate.to_bytes();
        let public_key_offset =
            std::mem::size_of::<adac::CertificateHeader>() + adac::ED448_PUBLIC_KEY_SIZE_UNPADDED;
        bytes[public_key_offset] ^= 0x01;

        assert!(matches!(
            AdacCertificate::from_bytes(bytes),
            Err(adac::AdacError::Encoding(message)) if message == "Invalid public key padding"
        ));
    }

    #[test]
    fn ml_dsa_44_chain_sig() {
        run_test_with(&TestSettings::default(), || {
            rust_crypto_chain_sig_test(
                MlDsa44Sha256,
                vec![
                    "resources/keys/MlDsa44Key-0.pk8",
                    "resources/keys/MlDsa44Key-1.pk8",
                    "resources/keys/MlDsa44Key-2.pk8",
                    "resources/keys/MlDsa44Key-3.pk8",
                ],
                Some("resources/chains/chain.MlDsa44"),
            )
        })
    }

    #[test]
    fn ml_dsa_44_root_sig() {
        rust_crypto_root_sig_test(
            MlDsa44Sha256,
            "resources/keys/MlDsa44Key-0.pk8",
            "resources/roots/root.MlDsa44",
        )
    }

    #[test]
    fn ml_dsa_65_chain_sig() {
        run_test_with(&TestSettings::default(), || {
            rust_crypto_chain_sig_test(
                MlDsa65Sha384,
                vec![
                    "resources/keys/MlDsa65Key-0.pk8",
                    "resources/keys/MlDsa65Key-1.pk8",
                    "resources/keys/MlDsa65Key-2.pk8",
                    "resources/keys/MlDsa65Key-3.pk8",
                ],
                Some("resources/chains/chain.MlDsa65"),
            )
        })
    }

    #[test]
    fn ml_dsa_65_root_sig() {
        run_test_with(&TestSettings::default(), || {
            rust_crypto_root_sig_test(
                MlDsa65Sha384,
                "resources/keys/MlDsa65Key-0.pk8",
                "resources/roots/root.MlDsa65",
            )
        })
    }

    #[test]
    fn ml_dsa_65_chain_rejects_nonzero_signature_padding() {
        run_test_with(&TestSettings::default(), || {
            let crypto = adac_crypto_rust::RustCryptoProvider::default();
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
        });
    }

    #[test]
    fn ml_dsa_87_chain_sig() {
        run_test_with(&TestSettings::default(), || {
            rust_crypto_chain_sig_test(
                MlDsa87Sha512,
                vec![
                    "resources/keys/MlDsa87Key-0.pk8",
                    "resources/keys/MlDsa87Key-1.pk8",
                    "resources/keys/MlDsa87Key-2.pk8",
                    "resources/keys/MlDsa87Key-3.pk8",
                ],
                Some("resources/chains/chain.MlDsa87"),
            )
        })
    }

    #[test]
    fn ml_dsa_87_root_sig() {
        run_test_with(&TestSettings::default(), || {
            rust_crypto_root_sig_test(
                MlDsa87Sha512,
                "resources/keys/MlDsa87Key-0.pk8",
                "resources/roots/root.MlDsa87",
            )
        })
    }

    #[test]
    fn rsa_3072_chain_sig() {
        rust_crypto_chain_sig_test(
            Rsa3072Sha256,
            vec![
                "resources/keys/Rsa3072Key-0.pk8",
                "resources/keys/Rsa3072Key-1.pk8",
                "resources/keys/Rsa3072Key-2.pk8",
                "resources/keys/Rsa3072Key-3.pk8",
            ],
            Some("resources/chains/chain.Rsa3072"),
        )
    }

    #[test]
    fn rsa_3072_root_sig() {
        rust_crypto_root_sig_test(
            Rsa3072Sha256,
            "resources/keys/Rsa3072Key-0.pk8",
            "resources/roots/root.Rsa3072",
        )
    }

    #[test]
    fn rsa_4096_chain_sig() {
        rust_crypto_chain_sig_test(
            Rsa4096Sha256,
            vec![
                "resources/keys/Rsa4096Key-0.pk8",
                "resources/keys/Rsa4096Key-1.pk8",
                "resources/keys/Rsa4096Key-2.pk8",
                "resources/keys/Rsa4096Key-3.pk8",
            ],
            Some("resources/chains/chain.Rsa4096"),
        )
    }

    #[test]
    fn rsa_4096_root_sig() {
        rust_crypto_root_sig_test(
            Rsa4096Sha256,
            "resources/keys/Rsa4096Key-0.pk8",
            "resources/roots/root.Rsa4096",
        )
    }

    #[test]
    fn sm2_chain_sig() {
        rust_crypto_chain_sig_test(
            SmSm2Sm3,
            vec![
                "resources/keys/Sm2Key-0.pk8",
                "resources/keys/Sm2Key-1.pk8",
                "resources/keys/Sm2Key-2.pk8",
                "resources/keys/Sm2Key-3.pk8",
            ],
            Some("resources/chains/chain.Sm2"),
        )
    }

    #[test]
    fn sm2_root_sig() {
        rust_crypto_root_sig_test(
            SmSm2Sm3,
            "resources/keys/Sm2Key-0.pk8",
            "resources/roots/root.Sm2",
        )
    }

    fn rust_crypto_chain_sig_test(
        key_type: KeyOptions,
        key_paths: Vec<&str>,
        test_file: Option<&str>,
    ) {
        let keys: Vec<Vec<u8>> = key_paths.iter().map(|p| load_key(p).unwrap().1).collect();
        let mut crypto = adac_crypto_rust::RustCryptoProvider::new(true);

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
        if let Some(t_file) = test_file {
            let reference = load_certificates(t_file).unwrap();
            assert_eq!(chain.len(), reference.len());
            for i in 0..chain.len() {
                let c = chain[i].to_bytes();
                let r = reference[i].to_bytes();
                assert_eq!(c.len(), r.len());
                assert_eq!(c, r);
            }
        }

        let save = save_certificates(&chain).unwrap();

        verify_chain(chain, &crypto).unwrap();

        let chain = read_certificates(save).unwrap();

        verify_chain(chain, &crypto).unwrap();
    }

    fn rust_crypto_root_sig_test(key_type: KeyOptions, key_path: &str, test_file: &str) {
        let key: Vec<u8> = load_key(key_path).unwrap().1;
        let mut crypto = adac_crypto_rust::RustCryptoProvider::new(true);

        let mut chain = vec![];
        let mut export = vec![];

        crypto
            .load_key(key_type, AdacKeyFormat::Pkcs8, key.clone().as_slice())
            .unwrap();
        let public_key = get_public_key(key_type, &key).unwrap();
        let (h, extensions) = crate::test_root_certificate_header(key_type);

        let certificate = AdacCertificate::sign(
            key_type,
            h,
            public_key.as_slice(),
            Some(extensions.as_slice()),
            &mut crypto,
        )
        .unwrap();
        export.extend_from_slice(adac::tlv_wrap(0x201, certificate.to_bytes()).as_slice());
        chain.push(certificate);

        // Compare certificates with chain from test file.
        let reference = load_certificates(test_file).unwrap();
        assert_eq!(chain.len(), reference.len());
        for i in 0..chain.len() {
            let c = chain[i].to_bytes();
            let r = reference[i].to_bytes();
            assert_eq!(c.len(), r.len());
            assert_eq!(c, r);
        }
        verify_chain(chain, &crypto).unwrap();
    }

    #[ignore]
    #[test]
    fn ecdsa_sign_test_rust() {
        let key_paths = [
            "resources/keys/EcdsaP384Key-0.pk8",
            "resources/keys/EcdsaP384Key-1.pk8",
            "resources/keys/EcdsaP384Key-2.pk8",
        ];

        let keys: Vec<Vec<u8>> = key_paths.iter().map(|p| load_key(p).unwrap().1).collect();
        let mut crypto = adac_crypto_rust::RustCryptoProvider::default();

        let key_type = EcdsaP384Sha384;
        let mut h = CertificateHeader {
            format_version: AdacVersion { major: 1, minor: 1 },
            role: AdacCrtRoleRoot,
            permissions_mask: [0xFFu8; 16],
            key_type,
            signature_type: key_type,
            usage: adac::CertificateUsage::AdacUsageNeutral,
            ..Default::default()
        };
        let mut chain = vec![];
        crypto
            .load_key(key_type, AdacKeyFormat::Pkcs8, keys[0].clone().as_slice())
            .unwrap();

        // Root CA
        let public_key = get_public_key(key_type, &keys[0]).unwrap();
        let certificate =
            AdacCertificate::sign(key_type, h, public_key.as_slice(), None, &mut crypto).unwrap();
        chain.push(certificate);
        let pem = save_certificates(&chain).unwrap();
        println!("{}", pem);
        let mut file = File::create(std::path::Path::new("../root.pem")).unwrap();
        file.write_all(pem.as_bytes()).unwrap();

        // Intermediate CA
        let public_key = get_public_key(key_type, &keys[1]).unwrap();
        for i in 0..4 {
            h.permissions_mask[i] = 0x00;
        }
        h.role = AdacCrtRoleInt;
        let certificate =
            AdacCertificate::sign(key_type, h, public_key.as_slice(), None, &mut crypto).unwrap();
        chain.push(certificate);
        let pem = save_certificates(&chain).unwrap();
        println!("{}", pem);
        let mut file = File::create(std::path::Path::new("../inter.pem")).unwrap();
        file.write_all(pem.as_bytes()).unwrap();

        // Load Intermediate CA Key
        crypto
            .load_key(key_type, AdacKeyFormat::Pkcs8, keys[1].clone().as_slice())
            .unwrap();
        let public_key = get_public_key(key_type, &keys[2]).unwrap();

        h.role = AdacCrtRoleLeaf;
        let soc_id = "0x00112233445566778899aabb00000000";
        let soc_id = hex::decode(soc_id.strip_prefix("0x").unwrap()).unwrap();
        let soc_id = u128::from_be_bytes(soc_id.as_slice().try_into().unwrap());
        h.soc_id.copy_from_slice(soc_id.to_le_bytes().as_ref());
        let permissions_mask = "0x0000000000000000FFFFFFFF00000000";
        let permissions_mask = hex::decode(permissions_mask.strip_prefix("0x").unwrap()).unwrap();
        let permissions_mask = u128::from_be_bytes(permissions_mask.as_slice().try_into().unwrap());
        h.permissions_mask
            .copy_from_slice(permissions_mask.to_le_bytes().as_ref());

        let certificate =
            AdacCertificate::sign(key_type, h, public_key.as_slice(), None, &mut crypto).unwrap();
        chain.push(certificate);
        let pem = save_certificates(&chain).unwrap();
        chain.pop();
        println!("{}", pem);
        let mut file = File::create(std::path::Path::new("../crt1.pem")).unwrap();
        file.write_all(pem.as_bytes()).unwrap();

        h.role = AdacCrtRoleLeaf;
        let soc_id = "0x0123456789AB0123456789AB00000000";
        let soc_id = hex::decode(soc_id.strip_prefix("0x").unwrap()).unwrap();
        let soc_id = u128::from_be_bytes(soc_id.as_slice().try_into().unwrap());
        h.soc_id.copy_from_slice(soc_id.to_le_bytes().as_ref());
        let permissions_mask = "0x0100000000000000FFFFFFFF00000000";
        let permissions_mask = hex::decode(permissions_mask.strip_prefix("0x").unwrap()).unwrap();
        let permissions_mask = u128::from_be_bytes(permissions_mask.as_slice().try_into().unwrap());
        h.permissions_mask
            .copy_from_slice(permissions_mask.to_le_bytes().as_ref());

        let certificate =
            AdacCertificate::sign(key_type, h, public_key.as_slice(), None, &mut crypto).unwrap();
        chain.push(certificate);
        let pem = save_certificates(&chain).unwrap();
        chain.pop();
        println!("{}", pem);
        let mut file = File::create(std::path::Path::new("../crt2.pem")).unwrap();
        file.write_all(pem.as_bytes()).unwrap();

        h.role = AdacCrtRoleLeaf;
        h.usage = AdacUsageRma;
        let soc_id = "0xBA9876543210BA987654321000000000";
        let soc_id = hex::decode(soc_id.strip_prefix("0x").unwrap()).unwrap();
        let soc_id = u128::from_be_bytes(soc_id.as_slice().try_into().unwrap());
        h.soc_id.copy_from_slice(soc_id.to_le_bytes().as_ref());
        let permissions_mask = "0x00000000000000000000000000000000";
        let permissions_mask = hex::decode(permissions_mask.strip_prefix("0x").unwrap()).unwrap();
        let permissions_mask = u128::from_be_bytes(permissions_mask.as_slice().try_into().unwrap());
        h.permissions_mask
            .copy_from_slice(permissions_mask.to_le_bytes().as_ref());

        let certificate =
            AdacCertificate::sign(key_type, h, public_key.as_slice(), None, &mut crypto).unwrap();
        chain.push(certificate);
        let pem = save_certificates(&chain).unwrap();
        chain.pop();
        println!("{}", pem);
        let mut file = File::create(std::path::Path::new("../crt3.pem")).unwrap();
        file.write_all(pem.as_bytes()).unwrap();
    }
}
