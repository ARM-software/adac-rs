// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::{AdacError, KeyOptions, KeyOptions::*};
use cryptoki::object::{Attribute, KeyType, MlDsaParameterSetType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use sha2::Digest;

pub(crate) fn parameter_set(key_type: KeyOptions) -> Result<MlDsaParameterSetType, AdacError> {
    match key_type {
        MlDsa44Sha256 => Ok(MlDsaParameterSetType::ML_DSA_44),
        MlDsa65Sha384 => Ok(MlDsaParameterSetType::ML_DSA_65),
        MlDsa87Sha512 => Ok(MlDsaParameterSetType::ML_DSA_87),
        _ => Err(AdacError::InconsistentCrypto),
    }
}

pub fn generate_keypair(
    session: &Session,
    key_type: KeyOptions,
) -> Result<(ObjectHandle, ObjectHandle), AdacError> {
    let public_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::ParameterSet(parameter_set(key_type)?.into()),
        Attribute::Verify(true),
    ];

    let private_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::Sign(true),
    ];

    session
        .generate_key_pair(
            &cryptoki::mechanism::Mechanism::MlDsaKeyPairGen,
            &public_key_template,
            &private_key_template,
        )
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))
}

pub fn import_key(
    session: &Session,
    key_type: KeyOptions,
    key: Vec<u8>,
) -> Result<(String, Vec<u8>, Vec<u8>, ObjectHandle, ObjectHandle), AdacError> {
    let (seed, public_key, spki) = adac_crypto::public::ml_dsa::pkcs8_import_parts(key_type, &key)?;
    let key_id = sha2::Sha256::digest(spki.as_slice());
    let kid = base16ct::lower::encode_string(&key_id);
    let parameter_set = parameter_set(key_type)?;

    let public_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::ParameterSet(parameter_set.into()),
        Attribute::Value(public_key),
        Attribute::Label(kid.clone().into_bytes()),
        Attribute::Id(key_id.to_vec()),
    ];

    let public = session
        .create_object(&public_key_template)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    let private_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::ParameterSet(parameter_set.into()),
        Attribute::Seed(seed),
        Attribute::Label(kid.clone().into_bytes()),
        Attribute::Id(key_id.to_vec()),
    ];

    let private = session
        .create_object(&private_key_template)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    Ok((kid, key_id.to_vec(), spki, private, public))
}

pub fn find_keypair(
    session: &Session,
    key_type: KeyOptions,
    key_id: &[u8],
) -> Result<(ObjectHandle, ObjectHandle), AdacError> {
    let private_key_search = vec![
        Attribute::Token(true),
        Attribute::Id(key_id.to_vec()),
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::ML_DSA),
    ];
    let private_keys = session
        .find_objects(&private_key_search)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    let private = super::unique_key_object(&private_keys, "private key", key_id)?;

    let public_key_search = vec![
        Attribute::Token(true),
        Attribute::Id(key_id.to_vec()),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::ML_DSA),
        Attribute::ParameterSet(parameter_set(key_type)?.into()),
    ];
    let public_keys = session
        .find_objects(&public_key_search)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    let public = super::unique_key_object(&public_keys, "public key", key_id)?;

    Ok((private, public))
}
