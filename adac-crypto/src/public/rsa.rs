// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::AdacPublicKey;
use adac::{AdacError, KeyOptions};
use der::Encode;
use pkcs8::DecodePrivateKey;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};

pub use rsa::pkcs1::ALGORITHM_OID;
use rsa::traits::PublicKeyParts;

pub fn from_adac(key_type: KeyOptions, adac: &[u8]) -> Result<AdacPublicKey, AdacError> {
    if adac.len() != adac::rsa_modulus_size(key_type)? {
        return Err(AdacError::InvalidLength);
    }
    let n = rsa::BigUint::from_bytes_be(adac);
    let f4 = rsa::BigUint::from_bytes_be(&[0x01u8, 0x00u8, 0x01u8]);

    adac::validate_rsa_modulus_bits(key_type, n.bits())?;

    let spki = rsa::RsaPublicKey::new(n, f4)
        .map_err(|e| AdacError::Encoding(format!("Rebuilding RSA public-key {}", e)))?
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Encoding SPKI {}", e)))?
        .to_vec();

    let adac = adac.to_vec();

    Ok(AdacPublicKey {
        key_type,
        spki,
        adac,
        oid: ALGORITHM_OID.to_der().unwrap(),
        curve: None,
    })
}

pub fn from_spki(spki: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let pk = rsa::RsaPublicKey::from_public_key_der(spki).map_err(|e| {
        AdacError::Encoding(format!("Error decoding RSA public key from SPKI: {}", e))
    })?;
    adac::validate_rsa_public_exponent(&pk.e().to_bytes_be())?;
    let (key_type, l) = adac::rsa_key_type_from_modulus_bits(pk.n().bits())?;
    let adac = pk.n().to_bytes_be();
    if adac.len() != l {
        return Err(AdacError::InconsistentCrypto);
    }

    Ok(AdacPublicKey {
        key_type,
        spki: spki.to_vec(),
        adac,
        oid: ALGORITHM_OID.to_der().unwrap(),
        curve: None,
    })
}

pub fn spki_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = rsa::RsaPrivateKey::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding RSA key from PKCS#8: {}", e)))?;
    adac::validate_rsa_public_exponent(&k.e().to_bytes_be())?;
    adac::rsa_key_type_from_modulus_bits(k.n().bits())?;
    let pk = k
        .to_public_key()
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Error encoding EdDSA key to SPKI: {}", e)))?
        .to_vec();
    Ok(pk)
}

pub fn adac_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = rsa::RsaPrivateKey::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding RSA key from PKCS#8: {}", e)))?;
    adac::validate_rsa_public_exponent(&k.e().to_bytes_be())?;
    adac::rsa_key_type_from_modulus_bits(k.n().bits())?;
    let pk = k.to_public_key().n().to_bytes_be();
    Ok(pk)
}

pub fn get_adac_from_spki(public_key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let key = rsa::RsaPublicKey::from_public_key_der(public_key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding RSA key from SPKI: {}", e)))?;
    adac::validate_rsa_public_exponent(&key.e().to_bytes_be())?;
    adac::rsa_key_type_from_modulus_bits(key.n().bits())?;
    Ok(key.n().to_bytes_be())
}
