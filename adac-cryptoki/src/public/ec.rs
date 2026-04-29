// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::ec_utils;
use crate::public::get_sec1_from_ec_point;
use adac::{AdacError, KeyOptions, KeyOptions::*};
use adac_crypto::public::{ec_dsa, ed_448, ed_25519};
use base64::prelude::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;

pub fn import_public_key(
    session: &Session,
    key_type: KeyOptions,
    public_key: &[u8],
) -> Result<ObjectHandle, AdacError> {
    let ec_params = adac_crypto::public::get_ec_params_oid_der(key_type)?;
    let pubkey = adac_crypto::public::get_sec1_octet_string_from_adac(key_type, public_key)?;

    let pubkey_template = vec![
        Attribute::Token(false),
        Attribute::Private(false),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Verify(true),
        Attribute::KeyType(ec_utils::get_ec_key_type(key_type)?),
        Attribute::EcParams(ec_params),
        Attribute::EcPoint(pubkey),
    ];

    session
        .create_object(&pubkey_template)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))
}

pub fn verify(
    session: &Session,
    key_type: KeyOptions,
    handle: ObjectHandle,
    data: &[u8],
    signature: &[u8],
) -> Result<(), AdacError> {
    let hash = crate::hash(session, key_type, data)?;

    match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => {
            session.verify(&Mechanism::Ecdsa, handle, hash.as_slice(), signature)
        }
        Ed25519Sha512 => {
            let params = EddsaParams::new(EddsaSignatureScheme::Ed25519ph(&[]));
            session.verify(
                &Mechanism::Eddsa(params),
                handle,
                hash.as_slice(),
                signature,
            )
        }
        Ed448Shake256 => {
            let params = EddsaParams::new(EddsaSignatureScheme::Ed448ph(&[]));
            session.verify(
                &Mechanism::Eddsa(params),
                handle,
                hash.as_slice(),
                signature,
            )
        }
        _ => return Err(AdacError::UnsupportedAlgorithm),
    }
    .map_err(|e| AdacError::CryptoProviderError(e.to_string()))
}

pub fn load_public_key(
    session: &Session,
    key_type: KeyOptions,
    key_handle: ObjectHandle,
) -> Result<Vec<u8>, AdacError> {
    let ec_params = adac_crypto::public::get_ec_params_oid_der(key_type)?;

    let params = session
        .get_attributes(key_handle, &[AttributeType::EcParams])
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?
        .pop()
        .ok_or(AdacError::CryptoProviderError(
            "EcParams not found".to_string(),
        ))?;
    let params = if let Attribute::EcParams(params) = params {
        params
    } else {
        return Err(AdacError::CryptoProviderError(
            "EcParams not found".to_string(),
        ));
    };

    if params.as_slice() != ec_params.as_slice() {
        return Err(AdacError::CryptoProviderError(format!(
            "OIDs do not match {} != {}",
            BASE64_STANDARD.encode(params),
            BASE64_STANDARD.encode(ec_params)
        )));
    }

    let ec_point = session
        .get_attributes(key_handle, &[AttributeType::EcPoint])
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?
        .pop()
        .ok_or(AdacError::CryptoProviderError(
            "EcPoint not found".to_string(),
        ))?;

    let ec_point = if let Attribute::EcPoint(point) = ec_point {
        match key_type {
            EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 | Ed25519Sha512 | Ed448Shake256 => {
                get_sec1_from_ec_point(key_type, point.as_slice())?
            }
            _ => return Err(AdacError::InconsistentCrypto),
        }
    } else {
        return Err(AdacError::CryptoProviderError(
            "EcPoint not found".to_string(),
        ));
    };

    let public_key = match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => {
            ec_dsa::from_sec1(key_type, ec_point.as_slice())?
                .get_spki()
                .to_vec()
        }
        Ed25519Sha512 => ed_25519::get_spki_from_ec_point(&ec_point)?,
        Ed448Shake256 => ed_448::get_spki_from_ec_point(&ec_point)?,
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };

    Ok(public_key)
}
