// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::AdacPublicKey;
use adac::{AdacError, KeyOptions::Ed25519Sha512};
use der::Encode;
use ed25519::pkcs8::DecodePrivateKey;
use spki::{DecodePublicKey, EncodePublicKey};

pub fn from_adac(adac: &[u8]) -> Result<AdacPublicKey, AdacError> {
    if adac.len() != adac::ED25519_PUBLIC_KEY_SIZE {
        return Err(AdacError::InvalidLength);
    }

    let mut raw: [u8; 32] = [0; adac::ED25519_PUBLIC_KEY_SIZE];
    raw.copy_from_slice(&adac[..adac::ED25519_PUBLIC_KEY_SIZE]);
    let pub_key = ed25519::pkcs8::PublicKeyBytes(raw);
    let spki = pub_key
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Encoding public key: {}", e)))?
        .to_vec();
    let oid = ed25519::pkcs8::ALGORITHM_OID.as_bytes().to_vec();

    Ok(AdacPublicKey {
        key_type: Ed25519Sha512,
        spki,
        adac: adac.to_vec(),
        oid,
        curve: None,
    })
}

pub fn from_spki(spki: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let adac = ed25519::pkcs8::PublicKeyBytes::try_from(spki)
        .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?
        .to_bytes()
        .to_vec();

    Ok(AdacPublicKey {
        key_type: Ed25519Sha512,
        spki: spki.to_vec(),
        adac,
        oid: ed25519::pkcs8::ALGORITHM_OID.to_der().unwrap(),
        curve: None,
    })
}

pub fn get_adac_from_spki(public_key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = ed25519::PublicKeyBytes::from_public_key_der(public_key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding EdDSA key from SPKI: {}", e)))?
        .to_bytes()
        .to_vec();
    Ok(k)
}

pub fn spki_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = ed25519::KeypairBytes::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding EdDSA key from PKCS#8: {}", e)))?;

    if let Some(pub_key) = k.public_key {
        let k = pub_key
            .to_public_key_der()
            .map_err(|e| AdacError::Encoding(format!("Error encoding EdDSA key to SPKI: {}", e)))?
            .to_vec();
        Ok(k)
    } else {
        Err(AdacError::UnsupportedAlgorithm)
    }
}

pub fn adac_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = ed25519::pkcs8::KeypairBytes::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding EdDSA key from PKCS#8: {}", e)))?;

    if let Some(pub_key) = k.public_key {
        Ok(pub_key.to_bytes().to_vec())
    } else {
        Err(AdacError::InconsistentCrypto)
    }
}

pub fn get_spki_from_ec_point(point: &[u8]) -> Result<Vec<u8>, AdacError> {
    let p: [u8; 32] = point
        .try_into()
        .map_err(|_| AdacError::InconsistentCrypto)?;
    Ok(from_adac(p.as_slice())?.get_spki().to_vec())
}
