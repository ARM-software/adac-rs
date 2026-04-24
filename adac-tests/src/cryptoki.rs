// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::AdacError;
use std::ops::{Deref, DerefMut};
use std::sync::{LazyLock, Mutex, MutexGuard};

// Tests use the first SoftHSM2 token with user pin '1234'. Initialize SoftHSM2 token with:
// softhsm2-util --init-token --free --label "test-token" --pin 1234 --so-pin 4321
static CRYPTO: LazyLock<Mutex<Option<adac_crypto_pkcs11::Pkcs11Provider>>> =
    LazyLock::new(|| Mutex::new(None));

struct TestPkcs11ProviderGuard(MutexGuard<'static, Option<adac_crypto_pkcs11::Pkcs11Provider>>);

impl Deref for TestPkcs11ProviderGuard {
    type Target = adac_crypto_pkcs11::Pkcs11Provider;

    fn deref(&self) -> &Self::Target {
        match self.0.as_ref() {
            Some(crypto) => crypto,
            None => unreachable!("test_pkcs11_provider initializes the PKCS#11 provider"),
        }
    }
}

impl DerefMut for TestPkcs11ProviderGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self.0.as_mut() {
            Some(crypto) => crypto,
            None => unreachable!("test_pkcs11_provider initializes the PKCS#11 provider"),
        }
    }
}

fn default_pkcs11_module() -> Result<String, AdacError> {
    if cfg!(target_os = "macos") {
        Ok("/opt/homebrew/lib/softhsm/libsofthsm2.so".to_string())
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        Ok("/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so".to_string())
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        Ok("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so".to_string())
    } else {
        Err(AdacError::CryptoProviderError(
            "No default PKCS#11 module path is defined for this platform".to_string(),
        ))
    }
}

fn create_test_pkcs11_provider() -> Result<adac_crypto_pkcs11::Pkcs11Provider, AdacError> {
    let module = if let Ok(module) = std::env::var("PKCS11_MODULE") {
        module
    } else {
        default_pkcs11_module()?
    };
    let pin = std::env::var("PKCS11_PIN").unwrap_or_else(|_| "1234".to_string());
    let slot = std::env::var("PKCS11_SLOT").ok();

    adac_crypto_pkcs11::Pkcs11Provider::new(module, pin, slot)
}

fn test_pkcs11_provider() -> Result<TestPkcs11ProviderGuard, AdacError> {
    let mut crypto = CRYPTO.lock().map_err(|_| {
        AdacError::CryptoProviderError("PKCS#11 test provider mutex poisoned".to_string())
    })?;
    if crypto.is_none() {
        *crypto = Some(create_test_pkcs11_provider()?);
    }
    Ok(TestPkcs11ProviderGuard(crypto))
}

#[cfg(test)]
mod tests {
    use super::test_pkcs11_provider;
    use adac::certificate::AdacCertificate;
    use adac::token::AdacToken;
    use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
    use adac::KeyOptions::*;
    use adac::{KeyOptions, TokenHeader};
    use adac_crypto::utils::{
        convert_public_key, load_certificates, load_key, save_certificates, verify_chain,
    };
    use std::ops::{Deref, DerefMut};

    #[test]
    fn cryptoki_ec_p256_chain_sig() {
        cryptoki_chain_sig_test(
            EcdsaP256Sha256,
            vec![
                (
                    "resources/keys/EcdsaP256Key-0.pk8",
                    "3de9684c5f3688b973441930f778952022a310028fc381195f49c53c1c470924",
                ),
                (
                    "resources/keys/EcdsaP256Key-1.pk8",
                    "bf72fee055bd0dc27a5aa2a819c15888af914358cc128bb90d42755754104e89",
                ),
                (
                    "resources/keys/EcdsaP256Key-2.pk8",
                    "90753295c838ac8e75e5b66e9757dbe4bc2a27680046eeecf0a98da1b942f56f",
                ),
                (
                    "resources/keys/EcdsaP256Key-3.pk8",
                    "8cdd55b5114cc2012b3edcf4116fbeef915ee8ff9600c331e3cd178971117316",
                ),
            ],
        );
    }

    #[test]
    fn cryptoki_ec_p384_chain_sig() {
        cryptoki_chain_sig_test(
            EcdsaP384Sha384,
            vec![
                (
                    "resources/keys/EcdsaP384Key-0.pk8",
                    "b1ac929e1db189bcc276f40f415365986356419933659b1952f7b5b5191a4656",
                ),
                (
                    "resources/keys/EcdsaP384Key-1.pk8",
                    "83c7d7d324b2ad2d25b554f3f11d3452a93cb12e10fe24a0f487c07a0b737ecc",
                ),
                (
                    "resources/keys/EcdsaP384Key-2.pk8",
                    "eac9747673fcf9e5371a70f5eec0f6d10a702c3593f380fadcaac538a51b1234",
                ),
                (
                    "resources/keys/EcdsaP384Key-3.pk8",
                    "6d722a1463e191704e66505d2a4deaf36fb8d49829eec347460881e103b5d77c",
                ),
            ],
        );
    }

    #[test]
    fn cryptoki_ec_p521_chain_sig() {
        cryptoki_chain_sig_test(
            EcdsaP521Sha512,
            vec![
                (
                    "resources/keys/EcdsaP521Key-0.pk8",
                    "c794759c165b5617bfa3fdad664bce2406713e211afde2f39b568872722021b3",
                ),
                (
                    "resources/keys/EcdsaP521Key-1.pk8",
                    "30dd513e70a9bc25dbdd8770444fb00947e492af38fb0438331e848be3e854c5",
                ),
                (
                    "resources/keys/EcdsaP521Key-2.pk8",
                    "17939db554c04454513d37036b1d291a18ef9f0376abcdacf997442608589e0e",
                ),
                (
                    "resources/keys/EcdsaP521Key-3.pk8",
                    "60d869f916772e4029e25e7f048ffe0466ee9178617f49bb169d9103102fe0d5",
                ),
            ],
        );
    }

    #[test]
    fn cryptoki_rsa_3072_chain_sig() {
        cryptoki_chain_sig_test(
            Rsa3072Sha256,
            vec![
                (
                    "resources/keys/Rsa3072Key-0.pk8",
                    "dcae48189f2b8ba53937bdfdf554d03ccd908419c80bfe96f5cfac5f94a04824",
                ),
                (
                    "resources/keys/Rsa3072Key-1.pk8",
                    "ce545f4a89e75b1f3b0c8ad18e15964036e9d9385f1a1047707c6bff9dbd9608",
                ),
                (
                    "resources/keys/Rsa3072Key-2.pk8",
                    "20561a124c60ad4cfe1f9487e9174a41a861874985f68a24f0b9441b0ccb2e8c",
                ),
                (
                    "resources/keys/Rsa3072Key-3.pk8",
                    "59f4e10b59acbb0894bd3825b538fa056a4226e96bf870950e4d8402b1adb937",
                ),
            ],
        );
    }

    #[test]
    fn cryptoki_rsa_4096_chain_sig() {
        cryptoki_chain_sig_test(
            Rsa4096Sha256,
            vec![
                (
                    "resources/keys/Rsa4096Key-0.pk8",
                    "824cd90f08ea16dfcdea53d03c72da59d8c6e264fec56d89c58b24cc07fd3912",
                ),
                (
                    "resources/keys/Rsa4096Key-1.pk8",
                    "c4217729cce664117bb8a693a4f1eb5da0a44a912827c3441777499a1fa6e386",
                ),
                (
                    "resources/keys/Rsa4096Key-2.pk8",
                    "8bf63e1f9964d5c1217654964e9c5b7ce8af14633f410a3947186399fde05322",
                ),
                (
                    "resources/keys/Rsa4096Key-3.pk8",
                    "bb8bdf655361d3faeb1eaa31561e13d89364f63ef22d4028844b3c3290627bdd",
                ),
            ],
        );
    }

    #[ignore]
    #[test]
    fn cryptoki_ed25519_chain_sig() {
        cryptoki_chain_sig_test(
            Ed25519Sha512,
            vec![
                (
                    "resources/keys/Ed25519Key-0.pk8",
                    "a66c5ce611c54559a6d684a57a143a013af450097ab4e64637a3fce0c54f5d10",
                ),
                (
                    "resources/keys/Ed25519Key-1.pk8",
                    "3536cbf5e927d0fc7d0be7929ce2182b6f8383a5c5e0d9d53772a14f69130da0",
                ),
                (
                    "resources/keys/Ed25519Key-2.pk8",
                    "a7f8f953c87141d6bc9a4cc0edc227276e1444dbf0d126d623c7b842c12383bb",
                ),
                (
                    "resources/keys/Ed25519Key-3.pk8",
                    "e08dd5a879ca542144ac5e383c347a17ecb2a77ae7e39e5de5cfc7baf67f6b11",
                ),
            ],
        );
    }

    fn cryptoki_chain_sig_test(key_type: KeyOptions, keys: Vec<(&str, &str)>) {
        let mut crypto = test_pkcs11_provider().unwrap();

        let mut chain = vec![];
        let mut export = vec![];
        let mut public_keys = vec![];
        let mut key_ids = vec![];

        for (key_path, str_kid) in keys {
            let key_id = base16ct::lower::decode_vec(str_kid).unwrap();

            let public_key = {
                if let Ok(pk) = crypto.load_key(key_type, AdacKeyFormat::KeyId, key_id.as_slice()) {
                    convert_public_key(key_type, pk).unwrap()
                } else {
                    let (kt, key) = load_key(key_path).unwrap();
                    assert_eq!(kt, key_type);
                    let (istr_kid, ikey_id, pk, _, _) = crypto.import_key(kt, key).unwrap();
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
            crypto
                .load_key(key_type, AdacKeyFormat::KeyId, key_ids[signer].as_slice())
                .unwrap();
            let h = crate::test_certificate_header(key_type, i);

            let certificate =
                AdacCertificate::sign(key_type, h, public_key.as_slice(), None, crypto.deref_mut())
                    .unwrap();
            export.extend_from_slice(adac::tlv_wrap(0x201, certificate.to_bytes()).as_slice());
            chain.push(certificate);
            signer = i;
        }

        assert_eq!(chain.len(), key_ids.len());
        println!("{}", save_certificates(&chain).unwrap());
        let rust_crypto = adac_crypto_rust::RustCryptoProvider::default();
        verify_chain(chain, &rust_crypto).unwrap();
    }

    #[test]
    fn cryptoki_token() {
        let mut crypto = test_pkcs11_provider().unwrap();
        let key_type = EcdsaP384Sha384;
        let key_path = "resources/keys/EcdsaP384Key-0.pk8";
        let str_kid = "b1ac929e1db189bcc276f40f415365986356419933659b1952f7b5b5191a4656";

        let key_id = base16ct::lower::decode_vec(str_kid).unwrap();
        let public_key = {
            if let Ok(pk) = crypto.load_key(key_type, AdacKeyFormat::KeyId, key_id.as_slice()) {
                convert_public_key(key_type, pk).unwrap()
            } else {
                let (kt, key) = load_key(key_path).unwrap();
                assert_eq!(kt, key_type);
                let (istr_kid, ikey_id, _pk, _, _) = crypto.import_key(kt, key).unwrap();
                assert_eq!(istr_kid, str_kid);
                assert_eq!(ikey_id, key_id);
                let pk = crypto
                    .load_key(key_type, AdacKeyFormat::KeyId, key_id.as_slice())
                    .unwrap();
                convert_public_key(key_type, pk).unwrap()
            }
        };

        let h = TokenHeader {
            signature_type: key_type,
            ..Default::default()
        };

        let challenge = vec![0x00u8; 32];
        let token =
            AdacToken::sign(key_type, h, None, challenge.as_slice(), crypto.deref_mut()).unwrap();

        token
            .verify(&public_key, challenge.as_slice(), crypto.deref())
            .unwrap();
    }

    #[test]
    fn ecdsa_p256_chain() {
        let crypto = test_pkcs11_provider().unwrap();

        let chain = load_certificates("resources/chains/chain.EcdsaP256").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, crypto.deref()).unwrap();
    }

    #[test]
    fn ecdsa_p384_chain() {
        let crypto = test_pkcs11_provider().unwrap();

        let chain = load_certificates("resources/chains/chain.EcdsaP384").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, crypto.deref()).unwrap();
    }

    #[test]
    fn ecdsa_p521_chain() {
        let crypto = test_pkcs11_provider().unwrap();

        let chain = load_certificates("resources/chains/chain.EcdsaP521").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, crypto.deref()).unwrap();
    }

    #[ignore]
    #[test]
    fn ed25519_chain() {
        let crypto = test_pkcs11_provider().unwrap();

        let chain = load_certificates("resources/chains/chain.Ed25519").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, crypto.deref()).unwrap();
    }

    #[ignore]
    #[test]
    fn ed448_chain() {
        let crypto = test_pkcs11_provider().unwrap();

        let chain = load_certificates("resources/chains/chain.Ed448").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, crypto.deref()).unwrap();
    }

    #[test]
    fn rsa_3072_chain() {
        let crypto = test_pkcs11_provider().unwrap();

        let chain = load_certificates("resources/chains/chain.Rsa3072").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, crypto.deref()).unwrap();
    }

    #[test]
    fn rsa_4096_chain() {
        let crypto = test_pkcs11_provider().unwrap();

        let chain = load_certificates("resources/chains/chain.Rsa4096").unwrap();
        assert_eq!(chain.len(), 4);
        verify_chain(chain, crypto.deref()).unwrap();
    }
}
