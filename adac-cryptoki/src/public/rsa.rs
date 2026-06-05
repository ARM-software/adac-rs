// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::{AdacError, KeyOptions};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use cryptoki::types::Ulong;
use rsa::pkcs8::EncodePublicKey;

pub fn import_public_key(
    session: &Session,
    key_type: KeyOptions,
    public_key: &[u8],
) -> Result<ObjectHandle, AdacError> {
    if public_key.len() != adac::rsa_modulus_size(key_type)? {
        return Err(AdacError::InvalidLength);
    }
    let modulus = rsa::BigUint::from_bytes_be(public_key);
    adac::validate_rsa_modulus_bits(key_type, modulus.bits())?;

    let exponent = vec![0x01u8, 0x00u8, 0x01u8];
    let pubkey_template = vec![
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Verify(true),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Modulus(public_key.to_vec()),
        Attribute::PublicExponent(exponent),
    ];

    session
        .create_object(&pubkey_template)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))
}

pub fn verify(
    session: &Session,
    _key_type: KeyOptions,
    handle: ObjectHandle,
    data: &[u8],
    signature: &[u8],
) -> Result<(), AdacError> {
    let hash = session
        .digest(&Mechanism::Sha256, data)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    match session.verify(
        &Mechanism::RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA256,
            mgf: PkcsMgfType::MGF1_SHA256,
            s_len: Ulong::from(32),
        }),
        handle,
        hash.as_slice(),
        signature,
    ) {
        Ok(()) => Ok(()),
        Err(e) => Err(AdacError::CryptoProviderError(e.to_string())),
    }
}

pub fn load_public_key(
    session: &Session,
    key_type: KeyOptions,
    key_handle: ObjectHandle,
) -> Result<Vec<u8>, AdacError> {
    let modulus = session
        .get_attributes(key_handle, &[AttributeType::Modulus])
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?
        .pop()
        .ok_or(AdacError::CryptoProviderError(
            "Missing RSA Modulus".to_string(),
        ))?;
    let modulus = if let Attribute::Modulus(modulus) = modulus {
        rsa::BigUint::from_bytes_be(modulus.as_slice())
    } else {
        return Err(AdacError::CryptoProviderError(
            "Invalid RSA Modulus".to_string(),
        ));
    };

    let exponent = session
        .get_attributes(key_handle, &[AttributeType::PublicExponent])
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?
        .pop()
        .ok_or(AdacError::CryptoProviderError(
            "Missing RSA Exponent".to_string(),
        ))?;
    let exponent = if let Attribute::PublicExponent(exponent) = exponent {
        rsa::BigUint::from_bytes_be(exponent.as_slice())
    } else {
        rsa::BigUint::from_bytes_be(&[0x01u8, 0x00u8, 0x01u8])
    };

    adac::validate_rsa_modulus_bits(key_type, modulus.bits())?;

    Ok(rsa::RsaPublicKey::new(modulus, exponent)
        .map_err(|e| AdacError::Encoding(format!("Rebuilding RSA public-key {}", e)))?
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Encoding SPKI {}", e)))?
        .to_vec())
}
