// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod ec_dsa;
pub mod ed_25519;
pub mod ed_448;
pub mod ml_dsa;
pub mod rsa;
pub mod sm;

use adac::{AdacError, ED25519_PUBLIC_KEY_SIZE, KeyOptions, KeyOptions::*};
use der::{Encode, asn1::BitString, oid::AssociatedOid};
use spki::{ObjectIdentifier, SubjectPublicKeyInfo};

#[derive(Clone, Debug)]
pub struct AdacPublicKey {
    key_type: KeyOptions,
    spki: Vec<u8>,
    adac: Vec<u8>,
    oid: Vec<u8>,
    curve: Option<Vec<u8>>,
}

impl AdacPublicKey {
    pub fn from_adac(key_type: KeyOptions, adac: &[u8]) -> Result<Self, AdacError> {
        match key_type {
            EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => {
                ec_dsa::from_adac(key_type, adac)
            }
            Ed25519Sha512 => ed_25519::from_adac(adac),
            Ed448Shake256 => ed_448::from_adac(adac),
            MlDsa44Sha256 | MlDsa65Sha384 | MlDsa87Sha512 => ml_dsa::from_adac(key_type, adac),
            Rsa3072Sha256 | Rsa4096Sha256 => rsa::from_adac(key_type, adac),
            SmSm2Sm3 => sm::from_adac(key_type, adac),
            _ => Err(AdacError::UnsupportedAlgorithm),
        }
    }

    pub fn from_spki(spki: &[u8]) -> Result<Self, AdacError> {
        let pki = spki::SubjectPublicKeyInfoOwned::try_from(spki)
            .map_err(|e| AdacError::Encoding(format!("Decoding SPKI: {}", e)))?;

        match pki.algorithm.oid {
            elliptic_curve::ALGORITHM_OID => {
                let pki: SubjectPublicKeyInfo<ObjectIdentifier, BitString> =
                    spki::SubjectPublicKeyInfo::try_from(spki)
                        .map_err(|e| AdacError::Encoding(format!("Decoding SPKI: {}", e)))?;
                let curve = pki
                    .algorithm
                    .parameters
                    .ok_or(AdacError::Encoding("Missing curve OID".to_string()))?;
                match curve {
                    p256::NistP256::OID | p384::NistP384::OID | p521::NistP521::OID => {
                        ec_dsa::from_spki(spki)
                    }
                    sm2::Sm2::OID => sm::from_spki(spki),
                    _ => Err(AdacError::Encoding("Unsupported curve".to_string())),
                }
            }
            ed25519::pkcs8::ALGORITHM_OID => ed_25519::from_spki(spki),
            ed448_goldilocks_plus::ALGORITHM_OID => ed_448::from_spki(spki),
            // ml_dsa::MlDsa44::ALGORITHM_IDENTIFIER
            crate::ML_DSA_44_OID => self::ml_dsa::from_spki(MlDsa44Sha256, spki),
            // ml_dsa::MlDsa65::ALGORITHM_IDENTIFIER
            crate::ML_DSA_65_OID => self::ml_dsa::from_spki(MlDsa65Sha384, spki),
            // ml_dsa::MlDsa87::ALGORITHM_IDENTIFIER
            crate::ML_DSA_87_OID => self::ml_dsa::from_spki(MlDsa87Sha512, spki),
            rsa::ALGORITHM_OID => rsa::from_spki(spki),
            _ => Err(AdacError::UnsupportedAlgorithm),
        }
    }

    pub fn get_key_type(&self) -> KeyOptions {
        self.key_type
    }

    pub fn get_adac(&self) -> &[u8] {
        self.adac.as_slice()
    }

    pub fn get_spki(&self) -> &[u8] {
        self.spki.as_slice()
    }

    pub fn get_oid(&self) -> &[u8] {
        self.oid.as_slice()
    }

    pub fn get_curve(&self) -> Option<&[u8]> {
        if let Some(c) = &self.curve {
            Some(c.as_slice())
        } else {
            None
        }
    }
}

pub fn get_curve_oid_der(key_type: KeyOptions) -> Result<Vec<u8>, AdacError> {
    match key_type {
        EcdsaP256Sha256 => p256::NistP256::OID,
        EcdsaP384Sha384 => p384::NistP384::OID,
        EcdsaP521Sha512 => p521::NistP521::OID,
        Ed25519Sha512 => ed25519::pkcs8::ALGORITHM_OID,
        Ed448Shake256 => crate::ED_448_OID,
        _ => return Err(AdacError::UnsupportedAlgorithm),
    }
    .to_der()
    .map_err(|e| AdacError::Encoding(e.to_string()))
}

pub fn get_ec_params_oid_der(key_type: KeyOptions) -> Result<Vec<u8>, AdacError> {
    // return get_curve_oid_der(key_type);
    match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => get_curve_oid_der(key_type),
        Ed25519Sha512 => Ok(vec![
            0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
        ]),
        Ed448Shake256 => Ok(vec![
            0x13, 0x0a, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64, 0x73, 0x34, 0x34, 0x38,
        ]),
        _ => Err(AdacError::UnsupportedAlgorithm),
    }
}

pub fn get_sec1_bytes_from_adac(
    key_type: KeyOptions,
    public_key: &[u8],
) -> Result<Vec<u8>, AdacError> {
    if key_type == Ed448Shake256 {
        Ok(adac::validate_public_key_padding(key_type, public_key)?.to_vec())
    } else if key_type == Ed25519Sha512 {
        Ok(public_key[0..ED25519_PUBLIC_KEY_SIZE].to_vec())
    } else {
        let mut pubkey = vec![0x04u8];
        pubkey.extend_from_slice(public_key);
        Ok(pubkey)
    }
}

pub fn get_sec1_octet_string_from_adac(
    key_type: KeyOptions,
    public_key: &[u8],
) -> Result<Vec<u8>, AdacError> {
    // match key_type {
    //     Ed448Shake256 | Ed25519Sha512 => Ok(get_sec1_bytes_from_adac(key_type, public_key)),
    //     _ => der::asn1::OctetString::new(get_sec1_bytes_from_adac(key_type, public_key))
    //         .map_err(|e| AdacError::Encoding(e.to_string()))?
    //         .to_der()
    //         .map_err(|e| AdacError::Encoding(e.to_string())),
    // }
    der::asn1::OctetString::new(get_sec1_bytes_from_adac(key_type, public_key)?)
        .map_err(|e| AdacError::Encoding(e.to_string()))?
        .to_der()
        .map_err(|e| AdacError::Encoding(e.to_string()))
}
