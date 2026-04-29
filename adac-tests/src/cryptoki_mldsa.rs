// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(test)]
mod tests {
    use adac::KeyOptions::*;
    use adac::certificate::AdacCertificate;
    use adac::token::AdacToken;
    use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
    use adac::{KeyOptions, TokenHeader};
    use adac_crypto::utils::{
        convert_public_key, load_certificates, load_key, save_certificates, verify_chain,
    };
    use adac_crypto_pkcs11::Pkcs11Provider;
    use std::ops::{Deref, DerefMut};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const ML_DSA_KEY_TYPES: [KeyOptions; 3] = [MlDsa44Sha256, MlDsa65Sha384, MlDsa87Sha512];

    static CRYPTO: LazyLock<Mutex<Option<Pkcs11Provider>>> = LazyLock::new(|| Mutex::new(None));

    struct TestPkcs11ProviderGuard(MutexGuard<'static, Option<Pkcs11Provider>>);

    impl Deref for TestPkcs11ProviderGuard {
        type Target = Pkcs11Provider;

        fn deref(&self) -> &Self::Target {
            match self.0.as_ref() {
                Some(crypto) => crypto,
                None => unreachable!("pkcs11_provider_from_env initializes the PKCS#11 provider"),
            }
        }
    }

    impl DerefMut for TestPkcs11ProviderGuard {
        fn deref_mut(&mut self) -> &mut Self::Target {
            match self.0.as_mut() {
                Some(crypto) => crypto,
                None => unreachable!("pkcs11_provider_from_env initializes the PKCS#11 provider"),
            }
        }
    }

    fn pkcs11_provider_from_env() -> TestPkcs11ProviderGuard {
        let mut provider = CRYPTO.lock().expect("PKCS#11 provider mutex poisoned");
        if provider.is_none() {
            let module = std::env::var("PKCS11_MODULE").expect("PKCS11_MODULE is required");
            let pin = std::env::var("PKCS11_PIN").expect("PKCS11_PIN is required");
            let slot = std::env::var("PKCS11_SLOT").ok();

            *provider = Some(
                Pkcs11Provider::new(module, pin, slot).expect("PKCS#11 provider should initialize"),
            );
        }

        TestPkcs11ProviderGuard(provider)
    }

    fn chain_path(key_type: KeyOptions) -> &'static str {
        match key_type {
            MlDsa44Sha256 => "resources/chains/chain.MlDsa44",
            MlDsa65Sha384 => "resources/chains/chain.MlDsa65",
            MlDsa87Sha512 => "resources/chains/chain.MlDsa87",
            _ => unreachable!("ML_DSA_KEY_TYPES only contains ML-DSA key types"),
        }
    }

    #[test]
    #[ignore = "requires a PKCS#11 token with ML-DSA support; set PKCS11_MODULE, PKCS11_PIN, and optionally PKCS11_SLOT"]
    fn cryptoki_mldsa_44() {
        cryptoki_mldsa_test(
            MlDsa44Sha256,
            vec![
                (
                    "resources/keys/MlDsa44Key-0.pk8",
                    "7afae22b009639ca43215826bba851bfe8949b22452d3a278323e1c39508e611",
                ),
                (
                    "resources/keys/MlDsa44Key-1.pk8",
                    "5aeed3ab30085a78fe129372796a12107f5e106e2b3a5d937620463e9314f333",
                ),
                (
                    "resources/keys/MlDsa44Key-2.pk8",
                    "30502d444226b2c4a6cf664d6ee6b168fc1fcd05e6bc6cbe639187391d50c11b",
                ),
                (
                    "resources/keys/MlDsa44Key-3.pk8",
                    "d38762f7834e5b3ef33ccb45d9157947af5f9e4671347eaf256fbb3ea3d1e205",
                ),
            ],
        );
    }

    #[test]
    #[ignore = "requires a PKCS#11 token with ML-DSA support; set PKCS11_MODULE, PKCS11_PIN, and optionally PKCS11_SLOT"]
    fn cryptoki_mldsa_65() {
        cryptoki_mldsa_test(
            MlDsa65Sha384,
            vec![
                (
                    "resources/keys/MlDsa65Key-0.pk8",
                    "c13e101bfa274ab54c847ab6f06f5d7a7672d8a244e4ddd251971f4859286b19",
                ),
                (
                    "resources/keys/MlDsa65Key-1.pk8",
                    "39191a431a77848c96ed38863ef018c9dd07ec060ab8b8651568fc311851e152",
                ),
                (
                    "resources/keys/MlDsa65Key-2.pk8",
                    "a6f9cbf7129cb1ede1ca460bf74a2e22ff4affb85ee51546e7b95e516b8a98e3",
                ),
                (
                    "resources/keys/MlDsa65Key-3.pk8",
                    "07cdc273a99928615e457c33381f274f43f830f0835a6109fa1067a69117b6e7",
                ),
            ],
        );
    }

    #[test]
    #[ignore = "requires a PKCS#11 token with ML-DSA support; set PKCS11_MODULE, PKCS11_PIN, and optionally PKCS11_SLOT"]
    fn cryptoki_mldsa_87() {
        cryptoki_mldsa_test(
            MlDsa87Sha512,
            vec![
                (
                    "resources/keys/MlDsa87Key-0.pk8",
                    "d68adae06de51ae80ec0bb8df8286a84aa273433259609c6640638331e0e64bc",
                ),
                (
                    "resources/keys/MlDsa87Key-1.pk8",
                    "5e97c3e29b3691d5c9269ea33aa0df2755c60f8fdfb142aeeb826a0bec426931",
                ),
                (
                    "resources/keys/MlDsa87Key-2.pk8",
                    "506cf49e7c8ce18176e5c290cbf45f221ab58c05c16dc4674381f22f1a284f61",
                ),
                (
                    "resources/keys/MlDsa87Key-3.pk8",
                    "b8ee725ff5d2b7733a6b2f1090eccd2ebf7191af30a18eb3f4ef0396aa3b9e76",
                ),
            ],
        );
    }

    fn cryptoki_mldsa_test(key_type: KeyOptions, keys: Vec<(&str, &str)>) {
        let mut provider = pkcs11_provider_from_env();
        let mut chain = vec![];
        let mut export = vec![];
        let mut public_keys = vec![];
        let mut key_ids = vec![];

        for (key_path, str_kid) in keys {
            let key_id = base16ct::lower::decode_vec(str_kid).unwrap();

            let public_key = {
                if let Ok(pk) = provider.load_key(key_type, AdacKeyFormat::KeyId, key_id.as_slice())
                {
                    convert_public_key(key_type, pk).unwrap()
                } else {
                    let (kt, key) = load_key(key_path).unwrap();
                    assert_eq!(kt, key_type);
                    let (istr_kid, ikey_id, pk, _, _) = provider.import_key(kt, key).unwrap();
                    assert_eq!(istr_kid, str_kid);
                    assert_eq!(ikey_id, key_id);
                    convert_public_key(key_type, pk).unwrap()
                }
            };
            public_keys.push(public_key);
            key_ids.push(key_id);
        }

        let mut signer = 0;
        for (i, public_key) in public_keys.iter().enumerate() {
            provider
                .load_key(key_type, AdacKeyFormat::KeyId, key_ids[signer].as_slice())
                .unwrap();
            let header = crate::test_certificate_header(key_type, i);
            let certificate = AdacCertificate::sign(
                key_type,
                header,
                public_key.as_slice(),
                None,
                provider.deref_mut(),
            )
            .unwrap();
            export.extend_from_slice(adac::tlv_wrap(0x201, certificate.to_bytes()).as_slice());
            chain.push(certificate);
            signer = i;
        }

        assert_eq!(chain.len(), key_ids.len());
        println!("{}", save_certificates(&chain).unwrap());
        let verifier = adac_crypto_rust::RustCryptoProvider::default();
        verify_chain(chain, &verifier).unwrap();

        provider
            .load_key(key_type, AdacKeyFormat::KeyId, key_ids[0].as_slice())
            .unwrap();
        let header = TokenHeader {
            signature_type: key_type,
            ..Default::default()
        };
        let challenge = vec![0x00u8; 32];
        let token = AdacToken::sign(
            key_type,
            header,
            None,
            challenge.as_slice(),
            provider.deref_mut(),
        )
        .unwrap();

        token
            .verify(&public_keys[0], challenge.as_slice(), provider.deref())
            .unwrap();
    }

    #[test]
    #[ignore = "requires a PKCS#11 token with ML-DSA support; set PKCS11_MODULE, PKCS11_PIN, and optionally PKCS11_SLOT"]
    fn pkcs11_mldsa_generated_keys_sign_and_verify() {
        let mut provider = pkcs11_provider_from_env();
        let message = b"ADAC PKCS#11 ML-DSA ignored integration test";

        for key_type in ML_DSA_KEY_TYPES {
            let (_kid, key_id, spki, _, _) = provider
                .generate_key(key_type)
                .expect("ML-DSA key generation should succeed");
            let loaded_public_key = provider
                .load_key(key_type, AdacKeyFormat::KeyId, key_id.as_slice())
                .expect("generated ML-DSA key should load by key ID");
            assert_eq!(spki, loaded_public_key);
            let public_key = adac_crypto::utils::convert_public_key(key_type, loaded_public_key)
                .expect("generated public key should convert to ADAC encoding");

            let signature = provider
                .sign(key_type, message)
                .expect("ML-DSA signing should succeed");
            provider
                .verify(
                    key_type,
                    public_key.as_slice(),
                    message,
                    signature.as_slice(),
                )
                .expect("ML-DSA verification should succeed");
        }
    }

    #[test]
    #[ignore = "requires a PKCS#11 token with ML-DSA support; set PKCS11_MODULE, PKCS11_PIN, and optionally PKCS11_SLOT"]
    fn pkcs11_mldsa_chains() {
        let provider = pkcs11_provider_from_env();

        for key_type in ML_DSA_KEY_TYPES {
            let chain = load_certificates(chain_path(key_type)).expect("ML-DSA chain should load");
            assert_eq!(chain.len(), 4);
            verify_chain(chain, provider.deref()).expect("ML-DSA certificate chain should verify");
        }
    }
}
