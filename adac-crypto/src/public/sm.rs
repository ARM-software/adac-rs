// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::AdacPublicKey;
use adac::KeyOptions::SmSm2Sm3;
use adac::{AdacError, KeyOptions};
use der::{Encode, oid::AssociatedOid};
use pkcs8::DecodePrivateKey;
use spki::{DecodePublicKey, EncodePublicKey};

pub const DISTID: &str = "adac@arm.com";

pub fn from_spki(spki: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let spki = sm2::PublicKey::from_public_key_der(spki)
        .map_err(|e| AdacError::Encoding(format!("Decoding SM2 SPKI: {}", e)))?;
    let adac = spki.to_sec1_bytes()[1..].to_vec();
    let spki = spki
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Re-encoding SM2 SPKI: {}", e)))?
        .to_vec();
    Ok(AdacPublicKey {
        key_type: SmSm2Sm3,
        spki,
        adac,
        oid: elliptic_curve::ALGORITHM_OID.to_der().unwrap(),
        curve: Some(sm2::Sm2::OID.to_der().unwrap()),
    })
}

pub fn from_adac(key_type: KeyOptions, adac: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(adac);
    let adac = adac.to_vec();
    let pkey = sm2::PublicKey::from_sec1_bytes(sec1.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Decoding SM2 SPKI: {}", e)))?;
    let spki = pkey
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Re-encoding SM2 SPKI: {}", e)))?
        .to_vec();

    Ok(AdacPublicKey {
        key_type,
        spki,
        adac,
        oid: elliptic_curve::ALGORITHM_OID.to_der().unwrap(),
        curve: Some(sm2::Sm2::OID.to_der().unwrap()),
    })
}

pub fn spki_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = sm2::SecretKey::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding RSA key from PKCS#8: {}", e)))?;
    let pk = k
        .public_key()
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Error encoding EdDSA key to SPKI: {}", e)))?
        .to_vec();
    Ok(pk)
}

pub fn adac_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = sm2::SecretKey::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding RSA key from PKCS#8: {}", e)))?;
    let pk = k.public_key().to_sec1_bytes()[1..].to_vec();
    Ok(pk)
}

pub fn get_adac_from_spki(public_key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = sm2::PublicKey::from_public_key_der(public_key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding RSA key from SPKI: {}", e)))?
        .to_sec1_bytes()[1..]
        .to_vec();
    Ok(k)
}
