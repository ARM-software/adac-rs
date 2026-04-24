// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::{AdacError, KeyOptions, KeyOptions::*, traits::*};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::unstable::signature::{
    ML_DSA_44, ML_DSA_65, ML_DSA_87, PqdsaKeyPair, PqdsaVerificationAlgorithm,
};
use aws_lc_rs::{digest::*, signature::*};

pub struct AwsLcKey {
    key_type: KeyOptions,
    key: Vec<u8>,
}

#[derive(Default)]
pub struct AwsLcCryptoProvider {
    current_key: Option<AwsLcKey>,
}

impl AwsLcCryptoProvider {
    fn load_ecdsa_key(&mut self, key_type: KeyOptions, key: &[u8]) -> Result<Vec<u8>, AdacError> {
        let key = key.to_vec();

        let alg = match key_type {
            EcdsaP256Sha256 => &ECDSA_P256_SHA256_FIXED_SIGNING,
            EcdsaP384Sha384 => &ECDSA_P384_SHA384_FIXED_SIGNING,
            EcdsaP521Sha512 => &ECDSA_P521_SHA512_FIXED_SIGNING,
            _ => return Err(AdacError::UnsupportedAlgorithm),
        };

        let k = EcdsaKeyPair::from_pkcs8(alg, key.as_slice())
            .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

        let public_key = k
            .public_key()
            .as_der()
            .map_err(|e| AdacError::Encoding(e.to_string()))?
            .as_ref()
            .to_vec();

        self.current_key = Some(AwsLcKey { key_type, key });
        Ok(public_key)
    }

    fn load_mldsa_key(&mut self, key_type: KeyOptions, key: &[u8]) -> Result<Vec<u8>, AdacError> {
        let key = key.to_vec();

        let alg = match key_type {
            MlDsa44Sha256 => &aws_lc_rs::unstable::signature::ML_DSA_44_SIGNING,
            MlDsa65Sha384 => &aws_lc_rs::unstable::signature::ML_DSA_65_SIGNING,
            MlDsa87Sha512 => &aws_lc_rs::unstable::signature::ML_DSA_87_SIGNING,
            _ => return Err(AdacError::UnsupportedAlgorithm),
        };

        let k = PqdsaKeyPair::from_pkcs8(alg, key.as_slice())
            .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

        let public_key = k
            .public_key()
            .as_der()
            .map_err(|e| AdacError::Encoding(e.to_string()))?
            .as_ref()
            .to_vec();

        self.current_key = Some(AwsLcKey { key_type, key });
        Ok(public_key)
    }
}

impl AdacCryptoProvider for AwsLcCryptoProvider {
    fn verify(
        &self,
        key_type: KeyOptions,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), AdacError> {
        let signature = adac::validate_signature_padding(key_type, signature)?;
        match key_type {
            EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => ecdsa_verify(
                match key_type {
                    EcdsaP256Sha256 => &ECDSA_P256_SHA256_FIXED_SIGNING,
                    EcdsaP384Sha384 => &ECDSA_P384_SHA384_FIXED_SIGNING,
                    EcdsaP521Sha512 => &ECDSA_P521_SHA512_FIXED_SIGNING,
                    _ => unreachable!("match arm restricts key_type"),
                },
                public_key,
                data,
                signature,
            ),
            MlDsa44Sha256 => mldsa_verify(&ML_DSA_44, public_key, data, signature),
            MlDsa65Sha384 => mldsa_verify(&ML_DSA_65, public_key, data, signature),
            MlDsa87Sha512 => mldsa_verify(&ML_DSA_87, public_key, data, signature),
            _ => Err(AdacError::UnsupportedAlgorithm),
        }
    }

    fn hash(&self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, AdacError> {
        let alg = match key_type {
            EcdsaP256Sha256 => &SHA256,
            EcdsaP384Sha384 => &SHA384,
            EcdsaP521Sha512 => &SHA512,
            MlDsa44Sha256 => &SHA256,
            MlDsa65Sha384 => &SHA384,
            MlDsa87Sha512 => &SHA512,
            _ => return Err(AdacError::UnsupportedAlgorithm),
        };
        Ok(digest(alg, data).as_ref().to_vec())
    }

    fn sign(&mut self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, AdacError> {
        let Some(current_key) = &self.current_key else {
            return Err(AdacError::InconsistentCrypto);
        };
        if current_key.key_type != key_type {
            return Err(AdacError::InconsistentCrypto);
        }

        match key_type {
            EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => {
                let alg = match key_type {
                    EcdsaP256Sha256 => &ECDSA_P256_SHA256_FIXED_SIGNING,
                    EcdsaP384Sha384 => &ECDSA_P384_SHA384_FIXED_SIGNING,
                    EcdsaP521Sha512 => &ECDSA_P521_SHA512_FIXED_SIGNING,
                    _ => return Err(AdacError::UnsupportedAlgorithm),
                };

                let k = EcdsaKeyPair::from_pkcs8(alg, current_key.key.as_slice())
                    .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

                let sig = k
                    .sign(&SystemRandom::new(), data)
                    .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;
                Ok(sig.as_ref().to_vec())
            }
            MlDsa44Sha256 | MlDsa65Sha384 | MlDsa87Sha512 => {
                let (alg, mut pad) = match key_type {
                    MlDsa44Sha256 => (&aws_lc_rs::unstable::signature::ML_DSA_44_SIGNING, vec![]),
                    MlDsa65Sha384 => (
                        &aws_lc_rs::unstable::signature::ML_DSA_65_SIGNING,
                        vec![0u8; 3],
                    ),
                    MlDsa87Sha512 => (
                        &aws_lc_rs::unstable::signature::ML_DSA_87_SIGNING,
                        vec![0u8; 1],
                    ),
                    _ => return Err(AdacError::UnsupportedAlgorithm),
                };

                let k = PqdsaKeyPair::from_pkcs8(alg, current_key.key.as_slice())
                    .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;
                let mut sig = vec![0u8; alg.signature_len()];
                k.sign(data, &mut sig)
                    .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;
                sig.append(&mut pad);

                Ok(sig)
            }
            _ => Err(AdacError::UnsupportedAlgorithm),
        }
    }

    fn load_key(
        &mut self,
        key_type: KeyOptions,
        format: AdacKeyFormat,
        key: &[u8],
    ) -> Result<Vec<u8>, AdacError> {
        if format != AdacKeyFormat::Pkcs8 {
            return Err(AdacError::CryptoProviderError(
                "Unsupported key format".to_string(),
            ));
        }
        match key_type {
            EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => {
                self.load_ecdsa_key(key_type, key)
            }
            MlDsa44Sha256 | MlDsa65Sha384 | MlDsa87Sha512 => self.load_mldsa_key(key_type, key),
            _ => Err(AdacError::UnsupportedAlgorithm),
        }
    }
}

fn ecdsa_verify(
    alg: &'static EcdsaVerificationAlgorithm,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), AdacError> {
    let mut pubkey = vec![0x04u8];
    pubkey.extend_from_slice(public_key);
    let pub_key = UnparsedPublicKey::new(alg, pubkey);
    pub_key
        .verify(data, signature)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))
}

fn mldsa_verify(
    alg: &PqdsaVerificationAlgorithm,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<(), AdacError> {
    alg.verify_sig(public_key, data, signature)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))
}
