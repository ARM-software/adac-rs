// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(any(test, feature = "hazmat-deterministic"))]
mod badrng;
pub mod ed_448;
pub mod sm;

use adac::{AdacError, KeyOptions, KeyOptions::*, traits::*};
use adac_crypto::public::{self, ml_dsa::KeyConverter};
use digest::{Digest, Update};
use ecdsa::{Signature, SigningKey, VerifyingKey};
use ed448_goldilocks_plus::PreHasherXof;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::DecodePrivateKey;
use rsa::signature::{RandomizedSigner as _, SignatureEncoding, Verifier as _};
use rsa::traits::PublicKeyParts;
use sha2::{Sha256, Sha384, Sha512};
use shake::Shake256;
use signature::Signer as _;
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use zeroize::Zeroizing;

pub struct RustCryptoKey {
    key_type: KeyOptions,
    key: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
pub struct RustCryptoProvider {
    deterministic: bool,
    current_key: Option<RustCryptoKey>,
}

fn rsa_public_modulus(
    key_type: KeyOptions,
    public_key: &[u8],
) -> Result<rsa::BoxedUint, AdacError> {
    if public_key.len() != adac::rsa_modulus_size(key_type)? {
        return Err(AdacError::InvalidLength);
    }

    let modulus = rsa::BoxedUint::from_be_slice_vartime(public_key);
    adac::validate_rsa_modulus_bits(key_type, modulus.bits() as usize)?;
    Ok(modulus)
}

fn validate_rsa_private_key_size(
    key_type: KeyOptions,
    key: &rsa::RsaPrivateKey,
) -> Result<(), AdacError> {
    adac::validate_rsa_modulus_bits(key_type, key.n().bits() as usize)?;
    adac::validate_rsa_public_exponent(&key.e_bytes())
}

impl RustCryptoProvider {
    pub fn new() -> Self {
        Self::default()
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "hazmat-deterministic"))]
    pub fn new_deterministic_for_tests() -> Self {
        RustCryptoProvider {
            deterministic: true,
            current_key: None,
        }
    }
}

impl AdacCryptoProvider for RustCryptoProvider {
    fn verify(
        &self,
        key_type: KeyOptions,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), AdacError> {
        let public_key = adac::validate_public_key_padding(key_type, public_key)?;
        let signature = adac::validate_signature_padding(key_type, signature)?;
        match key_type {
            EcdsaP256Sha256 => {
                let mut pubkey = vec![0x04u8];
                pubkey.extend_from_slice(public_key);
                let p = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey)
                    .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;
                let sig = p256::ecdsa::Signature::try_from(signature)
                    .map_err(|e| AdacError::Encoding(format!("Decoding signature: {}", e)))?;

                let hash = sha2::Sha256::digest(data);
                p.verify_prehash(&hash, &sig).map_err(|e| {
                    AdacError::CryptoProviderError(format!("Verifying signature: {}", e))
                })?
            }
            EcdsaP384Sha384 => {
                let mut pubkey = vec![0x04u8];
                pubkey.extend_from_slice(public_key);
                let p = p384::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey)
                    .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;
                let sig = p384::ecdsa::Signature::try_from(signature)
                    .map_err(|e| AdacError::Encoding(format!("Decoding signature: {}", e)))?;

                let hash = sha2::Sha384::digest(data);
                p.verify_prehash(&hash, &sig).map_err(|e| {
                    AdacError::CryptoProviderError(format!("Verifying signature: {}", e))
                })?
            }
            EcdsaP521Sha512 => {
                let mut pubkey = vec![0x04u8];
                pubkey.extend_from_slice(public_key);
                let p: VerifyingKey<NistP521> = VerifyingKey::<NistP521>::from_sec1_bytes(&pubkey)
                    .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;
                let sig = p521::ecdsa::Signature::try_from(signature)
                    .map_err(|e| AdacError::Encoding(format!("Decoding signature: {}", e)))?;

                let hash = sha2::Sha512::digest(data);
                p.verify_prehash(&hash, &sig).map_err(|e| {
                    AdacError::CryptoProviderError(format!("Verifying signature: {}", e))
                })?
            }
            Ed25519Sha512 => {
                let public_key_bytes = &public_key[0..ed25519_dalek::PUBLIC_KEY_LENGTH]
                    .try_into()
                    .map_err(|e| AdacError::Encoding(format!("Public key format: {}", e)))?;
                let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key_bytes)
                    .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;
                let sig = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|e| AdacError::Encoding(format!("Decoding signature: {}", e)))?;
                let prehash = sha2::Sha512::new().chain_update(data);
                vk.verify_prehashed(prehash, None, &sig).map_err(|e| {
                    AdacError::CryptoProviderError(format!("Signature verification: {}", e))
                })?;
            }
            Ed448Shake256 => {
                let public_key_bytes = &public_key[0..ed448_goldilocks_plus::PUBLIC_KEY_LENGTH]
                    .try_into()
                    .map_err(|e| AdacError::Encoding(format!("Public key format: {}", e)))?;
                let vk = ed448_goldilocks_plus::VerifyingKey::from_bytes(public_key_bytes)
                    .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;

                let sig = ed448_goldilocks_plus::Signature::try_from(signature)
                    .map_err(|e| AdacError::Encoding(format!("Decoding signature: {}", e)))?;
                let prehash = Shake256::default().chain(data);
                vk.verify_prehashed::<PreHasherXof<Shake256>>(&sig, None, prehash.into())
                    .map_err(|e| {
                        AdacError::CryptoProviderError(format!("Signature verification: {}", e))
                    })?;
            }
            MlDsa44Sha256 => {
                let vk_bytes = ml_dsa::EncodedVerifyingKey::<MlDsa44>::try_from(public_key)
                    .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;
                let vk = ml_dsa::VerifyingKey::<MlDsa44>::decode(&vk_bytes);

                let sig_bytes = ml_dsa::EncodedSignature::<MlDsa44>::try_from(signature)
                    .map_err(|e| AdacError::Encoding(format!("Decoding signature: {}", e)))?;
                let sig = ml_dsa::Signature::<MlDsa44>::decode(&sig_bytes)
                    .ok_or(AdacError::Encoding("Invalid signature".to_string()))?;
                if !vk.verify_with_context(data, &[], &sig) {
                    return Err(AdacError::InvalidSignature);
                }
            }
            MlDsa65Sha384 => {
                let vk_bytes = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
                    .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;
                let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&vk_bytes);

                let sig_bytes = ml_dsa::EncodedSignature::<MlDsa65>::try_from(signature)
                    .map_err(|e| AdacError::Encoding(format!("Decoding signature: {}", e)))?;
                let sig = ml_dsa::Signature::<MlDsa65>::decode(&sig_bytes)
                    .ok_or(AdacError::Encoding("Invalid signature".to_string()))?;
                if !vk.verify_with_context(data, &[], &sig) {
                    return Err(AdacError::InvalidSignature);
                }
            }
            MlDsa87Sha512 => {
                let vk_bytes = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key)
                    .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;
                let vk = ml_dsa::VerifyingKey::<MlDsa87>::decode(&vk_bytes);

                let sig_bytes = ml_dsa::EncodedSignature::<MlDsa87>::try_from(signature)
                    .map_err(|e| AdacError::Encoding(format!("Decoding signature: {}", e)))?;
                let sig = ml_dsa::Signature::<MlDsa87>::decode(&sig_bytes)
                    .ok_or(AdacError::Encoding("Invalid signature".to_string()))?;
                if !vk.verify_with_context(data, &[], &sig) {
                    return Err(AdacError::InvalidSignature);
                }
            }
            Rsa3072Sha256 | Rsa4096Sha256 => {
                let n = rsa_public_modulus(key_type, public_key)?;
                let f4 = rsa::BoxedUint::from_be_slice_vartime(&adac::RSA_PUBLIC_EXPONENT);
                let pk = rsa::RsaPublicKey::new(n, f4).map_err(|e| {
                    AdacError::Encoding(format!("Rebuilding RSA public key: {}", e))
                })?;
                let vk = rsa::pss::VerifyingKey::<rsa::sha2::Sha256>::new(pk);
                let sig = rsa::pss::Signature::try_from(signature)
                    .map_err(|e| AdacError::Encoding(format!("Decoding signature: {}", e)))?;
                vk.verify(data, &sig).map_err(|e| {
                    AdacError::CryptoProviderError(format!("Signature verification: {}", e))
                })?;
            }
            SmSm2Sm3 => {
                let mut pubkey = vec![0x04u8];
                pubkey.extend_from_slice(public_key);
                let vk =
                    sm2::dsa::VerifyingKey::from_sec1_bytes(public::sm::DISTID, pubkey.as_slice())
                        .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;
                let sig = sm2::dsa::Signature::try_from(signature)
                    .map_err(|e| AdacError::Encoding(format!("Decoding signature: {}", e)))?;
                vk.verify(data, &sig).map_err(|e| {
                    AdacError::CryptoProviderError(format!("SM2 Signature verification: {}", e))
                })?;
            }
            _ => return Err(AdacError::UnsupportedAlgorithm),
        }
        Ok(())
    }

    fn hash(&self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, AdacError> {
        Ok(match key_type {
            EcdsaP256Sha256 => Sha256::digest(data).to_vec(),
            EcdsaP384Sha384 => Sha384::digest(data).to_vec(),
            EcdsaP521Sha512 => Sha512::digest(data).to_vec(),
            Ed25519Sha512 => Sha512::digest(data).to_vec(),
            Ed448Shake256 => ed_448::shake256_digest(data),
            MlDsa44Sha256 => Sha256::digest(data).to_vec(),
            MlDsa65Sha384 => Sha384::digest(data).to_vec(),
            MlDsa87Sha512 => Sha512::digest(data).to_vec(),
            Rsa3072Sha256 => Sha256::digest(data).to_vec(),
            Rsa4096Sha256 => Sha256::digest(data).to_vec(),
            SmSm2Sm3 => sm::sm3_digest(data),
            _ => return Err(AdacError::UnsupportedAlgorithm),
        })
    }

    fn sign(&mut self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, AdacError> {
        let Some(current_key) = &self.current_key else {
            return Err(AdacError::InconsistentCrypto);
        };
        if current_key.key_type != key_type {
            return Err(AdacError::InconsistentCrypto);
        }

        let sig = match key_type {
            EcdsaP256Sha256 => {
                let pkey = p256::ecdsa::SigningKey::from_pkcs8_der(current_key.key.as_slice())
                    .map_err(|e| AdacError::Encoding(format!("Decoding private key: {}", e)))?;
                <SigningKey<NistP256> as PrehashSigner<Signature<NistP256>>>::sign_prehash(
                    &pkey,
                    self.hash(key_type, data)?.as_slice(),
                )
                .map_err(|e| AdacError::CryptoProviderError(format!("Signing: {}", e)))?
                .to_bytes()
                .to_vec()
            }
            EcdsaP384Sha384 => {
                let pkey = p384::ecdsa::SigningKey::from_pkcs8_der(current_key.key.as_slice())
                    .map_err(|e| AdacError::Encoding(format!("Decoding private key: {}", e)))?;
                let hash = self.hash(key_type, data)?;
                <SigningKey<NistP384> as PrehashSigner<Signature<NistP384>>>::sign_prehash(
                    &pkey,
                    hash.as_slice(),
                )
                .map_err(|e| AdacError::CryptoProviderError(format!("Signing: {}", e)))?
                .to_bytes()
                .to_vec()
            }
            // NistP521 does not implement the DigestPrimitive trait.
            // EcdsaP521Sha512 => {
            //     let pkey = SigningKey::<NistP521>::from_pkcs8_der(current_key.key.as_slice())
            //         .map_err(|e| AdacError::Encoding(format!("Decoding private key: {}", e)))?.into();
            //     <SigningKey<NistP521> as PrehashSigner<Signature<NistP521>>>::sign_prehash(
            //         &pkey,
            //         self.hash(key_type, data)?.as_slice(),
            //     )
            //     .map_err(|e| AdacError::CryptoProviderError(format!("Signing: {}", e)))?
            //     .to_bytes()
            //     .to_vec()
            // }
            Ed25519Sha512 => {
                let pkey = ed25519_dalek::SigningKey::from_pkcs8_der(current_key.key.as_slice())
                    .map_err(|e| AdacError::Encoding(format!("Decoding private key: {}", e)))?;
                let prehash = sha2::Sha512::new().chain_update(data);
                pkey.sign_prehashed(prehash, None)
                    .map_err(|e| AdacError::CryptoProviderError(format!("Signing: {}", e)))?
                    .to_bytes()
                    .to_vec()
            }
            Ed448Shake256 => {
                let (secret_key, verifying_key, _) = ed_448::load_key(current_key.key.as_slice())?;
                let k = ed448_goldilocks_plus::KeypairBytes {
                    secret_key,
                    verifying_key,
                };
                let pkey = ed448_goldilocks_plus::SigningKey::try_from(k)
                    .map_err(|e| AdacError::Encoding(format!("Decoding private key: {}", e)))?;
                let prehash = Shake256::default().chain(data);
                let mut sig = pkey
                    .sign_prehashed::<PreHasherXof<Shake256>>(None, prehash.into())
                    .map_err(|e| AdacError::CryptoProviderError(format!("Signing: {}", e)))?
                    .to_bytes()
                    .to_vec();
                sig.append(&mut vec![0u8; 2]);
                sig
            }
            MlDsa44Sha256 => {
                let pk = KeyConverter::<MlDsa44>::fix_pkcs8_der(&current_key.key)?;
                let sk = ml_dsa::SigningKey::<MlDsa44>::from_pkcs8_der(&pk)
                    .map_err(|e| AdacError::Encoding(format!("Decoding private key: {}", e)))?;
                ml_dsa::signature::Signer::try_sign(&sk, data)
                    .map_err(|e| AdacError::CryptoProviderError(format!("Signing: {}", e)))?
                    .encode()
                    .to_vec()
            }
            MlDsa65Sha384 => {
                let pk = KeyConverter::<MlDsa65>::fix_pkcs8_der(&current_key.key)?;
                let sk = ml_dsa::SigningKey::<MlDsa65>::from_pkcs8_der(&pk)
                    .map_err(|e| AdacError::Encoding(format!("Decoding private key: {}", e)))?;
                let mut sig = ml_dsa::signature::Signer::try_sign(&sk, data)
                    .map_err(|e| AdacError::CryptoProviderError(format!("Signing: {}", e)))?
                    .encode()
                    .to_vec();
                sig.append(&mut vec![0u8; 3]);
                sig
            }
            MlDsa87Sha512 => {
                let pk = KeyConverter::<MlDsa87>::fix_pkcs8_der(&current_key.key)?;
                let sk = ml_dsa::SigningKey::<MlDsa87>::from_pkcs8_der(&pk)
                    .map_err(|e| AdacError::Encoding(format!("Decoding private key: {}", e)))?;
                let mut sig = ml_dsa::signature::Signer::try_sign(&sk, data)
                    .map_err(|e| AdacError::CryptoProviderError(format!("Signing: {}", e)))?
                    .encode()
                    .to_vec();
                sig.append(&mut vec![0u8; 1]);
                sig
            }
            Rsa3072Sha256 | Rsa4096Sha256 => {
                let k = rsa::RsaPrivateKey::from_pkcs8_der(current_key.key.as_slice())
                    .map_err(|e| AdacError::Encoding(format!("Decoding private key: {}", e)))?;
                validate_rsa_private_key_size(key_type, &k)?;
                let sk = rsa::pss::SigningKey::<rsa::sha2::Sha256>::new(k);
                if self.deterministic {
                    #[cfg(any(test, feature = "hazmat-deterministic"))]
                    {
                        let mut rng = badrng::BadRng {};
                        sk.sign_with_rng(&mut rng, data).to_vec()
                    }
                    #[cfg(not(any(test, feature = "hazmat-deterministic")))]
                    {
                        return Err(AdacError::CryptoProviderError(
                            "Deterministic RSA-PSS signing is disabled".to_string(),
                        ));
                    }
                } else {
                    let mut rng = rand::rng();
                    sk.sign_with_rng(&mut rng, data).to_vec()
                }
            }
            SmSm2Sm3 => {
                let k = sm2::SecretKey::from_pkcs8_der(current_key.key.as_slice())
                    .map_err(|e| AdacError::Encoding(format!("Decoding SM2 private key: {}", e)))?;
                let sk = sm2::dsa::SigningKey::new(public::sm::DISTID, &k)
                    .map_err(|e| AdacError::Encoding(format!("Deriving SM2 signing key: {}", e)))?;
                if self.deterministic {
                    sk.sign(data).to_vec()
                } else {
                    sk.try_sign_with_rng(&mut rand::rng(), data)
                        .map_err(|e| AdacError::CryptoProviderError(format!("SM2 signing: {}", e)))?
                        .to_vec()
                }
            }
            _ => return Err(AdacError::UnsupportedAlgorithm),
        };
        Ok(sig)
    }

    fn load_key(
        &mut self,
        key_type: KeyOptions,
        format: AdacKeyFormat,
        key: &[u8],
    ) -> Result<Vec<u8>, AdacError> {
        if format == AdacKeyFormat::Pkcs8 {
            let key = Zeroizing::new(key.to_vec());

            let public_key = match key_type {
                EcdsaP256Sha256 => public::ec_dsa::spki_from_pkcs8::<NistP256>(&key)?,
                EcdsaP384Sha384 => public::ec_dsa::spki_from_pkcs8::<NistP384>(&key)?,
                EcdsaP521Sha512 => public::ec_dsa::spki_from_pkcs8::<NistP521>(&key)?,
                Ed25519Sha512 => public::ed_25519::spki_from_pkcs8(&key)?,
                Ed448Shake256 => public::ed_448::spki_from_pkcs8(&key)?,
                MlDsa44Sha256 => public::ml_dsa::spki_from_pkcs8::<MlDsa44>(&key)?,
                MlDsa65Sha384 => public::ml_dsa::spki_from_pkcs8::<MlDsa65>(&key)?,
                MlDsa87Sha512 => public::ml_dsa::spki_from_pkcs8::<MlDsa87>(&key)?,
                Rsa3072Sha256 | Rsa4096Sha256 => {
                    let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(key.as_slice())
                        .map_err(|e| AdacError::Encoding(format!("Decoding private key: {}", e)))?;
                    validate_rsa_private_key_size(key_type, &rsa_key)?;
                    public::rsa::spki_from_pkcs8(&key)?
                }
                SmSm2Sm3 => public::sm::spki_from_pkcs8(&key)?,
                _ => return Err(AdacError::UnsupportedAlgorithm),
            };

            self.current_key = Some(RustCryptoKey { key_type, key });
            Ok(public_key)
        } else {
            Err(AdacError::CryptoProviderError(
                "Unsupported key format".to_string(),
            ))
        }
    }
}
