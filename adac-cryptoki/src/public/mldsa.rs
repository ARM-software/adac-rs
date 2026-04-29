// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::{AdacError, KeyOptions, KeyOptions::*};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

fn read_attribute(
    session: &Session,
    key_handle: ObjectHandle,
    attribute_type: AttributeType,
    attribute_name: &str,
) -> Result<Attribute, AdacError> {
    session
        .get_attributes(key_handle, &[attribute_type])
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?
        .pop()
        .ok_or(AdacError::CryptoProviderError(format!(
            "{attribute_name} not found"
        )))
}

fn mldsa_mechanism() -> Mechanism<'static> {
    Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, None))
}

fn zero_padding_len(key_type: KeyOptions) -> Result<usize, AdacError> {
    match key_type {
        MlDsa44Sha256 => Ok(0),
        MlDsa65Sha384 => Ok(adac::MLDSA_65_SIGNATURE_SIZE - adac::MLDSA_65_SIGNATURE_UNPADDED),
        MlDsa87Sha512 => Ok(adac::MLDSA_87_SIGNATURE_SIZE - adac::MLDSA_87_SIGNATURE_UNPADDED),
        _ => Err(AdacError::InconsistentCrypto),
    }
}

pub fn pad_signature(key_type: KeyOptions, mut signature: Vec<u8>) -> Result<Vec<u8>, AdacError> {
    signature.extend(std::iter::repeat_n(0, zero_padding_len(key_type)?));
    Ok(signature)
}

pub fn import_public_key(
    session: &Session,
    key_type: KeyOptions,
    public_key: &[u8],
) -> Result<ObjectHandle, AdacError> {
    let public_key = adac::validate_public_key_padding(key_type, public_key)?;
    let pubkey_template = vec![
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Verify(true),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::ParameterSet(crate::private::mldsa::parameter_set(key_type)?.into()),
        Attribute::Value(public_key.to_vec()),
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
    session
        .verify(&mldsa_mechanism(), handle, data, signature)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))
}

pub fn load_public_key(
    session: &Session,
    key_type: KeyOptions,
    key_handle: ObjectHandle,
) -> Result<Vec<u8>, AdacError> {
    let parameter_set = read_attribute(
        session,
        key_handle,
        AttributeType::ParameterSet,
        "ParameterSet",
    )?;
    if parameter_set
        != Attribute::ParameterSet(crate::private::mldsa::parameter_set(key_type)?.into())
    {
        return Err(AdacError::InconsistentCrypto);
    }

    if let Ok(Attribute::PublicKeyInfo(spki)) = read_attribute(
        session,
        key_handle,
        AttributeType::PublicKeyInfo,
        "PublicKeyInfo",
    ) {
        return Ok(spki);
    }

    let public_key = read_attribute(session, key_handle, AttributeType::Value, "Value")?;
    let public_key = if let Attribute::Value(public_key) = public_key {
        public_key
    } else {
        return Err(AdacError::CryptoProviderError(
            "Invalid ML-DSA public key value".to_string(),
        ));
    };

    adac_crypto::public::AdacPublicKey::from_adac(key_type, public_key.as_slice())
        .map(|public_key| public_key.get_spki().to_vec())
}
