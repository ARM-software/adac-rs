// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::ec_utils::get_ec_key_type;
use adac::KeyOptions::{
    EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512, Ed448Shake256, Ed25519Sha512,
};
use adac::{AdacError, KeyOptions};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use der::Encode;
use der::oid::AssociatedOid;
use pkcs8::{DecodePrivateKey, PrivateKeyInfo};
use sha2::Digest;
use spki::EncodePublicKey;

pub fn generate_ecdsa_keypair(
    session: &Session,
    key_type: KeyOptions,
) -> Result<(ObjectHandle, ObjectHandle), AdacError> {
    let oid = adac_crypto::public::get_curve_oid_der(key_type)?;

    let public_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::KeyType(KeyType::EC),
        Attribute::Verify(true),
        Attribute::EcParams(oid),
    ];

    let private_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
    ];

    session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &public_key_template,
            &private_key_template,
        )
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))
}

pub fn generate_eddsa_keypair(
    session: &Session,
    key_type: KeyOptions,
) -> Result<(ObjectHandle, ObjectHandle), AdacError> {
    let oid = adac_crypto::public::get_ec_params_oid_der(key_type)?;

    let public_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::KeyType(KeyType::EC_EDWARDS),
        Attribute::Verify(true),
        Attribute::EcParams(oid),
    ];

    let private_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
    ];

    session
        .generate_key_pair(
            &Mechanism::EccEdwardsKeyPairGen,
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
    let pk =
        PrivateKeyInfo::try_from(key.as_slice()).map_err(|e| AdacError::Encoding(e.to_string()))?;

    let oid = if pk.algorithm.oid != elliptic_curve::ALGORITHM_OID {
        pk.algorithm.oid
    } else {
        pk.algorithm
            .parameters_oid()
            .map_err(|e| AdacError::Encoding(e.to_string()))?
    };

    let (pk, pubk, spki) = match (key_type, oid) {
        (EcdsaP256Sha256, p256::NistP256::OID) => {
            let pk = p256::SecretKey::from_pkcs8_der(key.as_slice())
                .map_err(|e| AdacError::Encoding(e.to_string()))?;
            (
                pk.to_bytes().to_vec(),
                pk.public_key().to_sec1_bytes().to_vec(),
                pk.public_key()
                    .to_public_key_der()
                    .map_err(|e| AdacError::Encoding(e.to_string()))?
                    .to_vec(),
            )
        }
        (EcdsaP384Sha384, p384::NistP384::OID) => {
            let pk = p384::SecretKey::from_pkcs8_der(key.as_slice())
                .map_err(|e| AdacError::Encoding(e.to_string()))?;
            (
                pk.to_bytes().to_vec(),
                pk.public_key().to_sec1_bytes().to_vec(),
                pk.public_key()
                    .to_public_key_der()
                    .map_err(|e| AdacError::Encoding(e.to_string()))?
                    .to_vec(),
            )
        }
        (EcdsaP521Sha512, p521::NistP521::OID) => {
            let pk = p521::SecretKey::from_pkcs8_der(key.as_slice())
                .map_err(|e| AdacError::Encoding(e.to_string()))?;
            (
                pk.to_bytes().to_vec(),
                pk.public_key().to_sec1_bytes().to_vec(),
                pk.public_key()
                    .to_public_key_der()
                    .map_err(|e| AdacError::Encoding(e.to_string()))?
                    .to_vec(),
            )
        }
        (Ed25519Sha512, ed25519::pkcs8::ALGORITHM_OID) => {
            let pk = ed25519::pkcs8::KeypairBytes::from_pkcs8_der(key.as_slice())
                .map_err(|e| AdacError::Encoding(e.to_string()))?;
            let pubk = pk.public_key.unwrap();
            (
                pk.secret_key.to_vec(),
                pubk.0.to_vec(),
                pubk.to_public_key_der()
                    .map_err(|e| AdacError::Encoding(e.to_string()))?
                    .to_vec(),
            )
        }
        (Ed448Shake256, adac_crypto::ED_448_OID) => {
            if let (secret_key, Some(public_key), Some(spki)) =
                adac_crypto_rust::ed_448::load_key(key.as_slice())?
            {
                (secret_key.to_vec(), public_key.to_vec(), spki)
            } else {
                return Err(AdacError::Encoding("No public key".to_string()));
            }
        }
        _ => return Err(AdacError::InconsistentCrypto),
    };
    let ec_params = adac_crypto::public::get_ec_params_oid_der(key_type)?;
    let pubk = der::asn1::OctetString::new(pubk)
        .map_err(|e| AdacError::Encoding(e.to_string()))?
        .to_der()
        .map_err(|e| AdacError::Encoding(e.to_string()))?;

    let key_id = sha2::Sha256::digest(spki.as_slice());
    let kid = base16ct::lower::encode_string(&key_id);
    let kt = get_ec_key_type(key_type)?;

    let pub_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        Attribute::KeyType(kt),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::EcParams(ec_params.clone()),
        Attribute::EcPoint(pubk),
        Attribute::Label(kid.clone().into_bytes()),
        Attribute::Id(key_id.to_vec()),
    ];

    let public = session
        .create_object(&pub_key_template)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    let private_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::KeyType(kt),
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::EcParams(ec_params),
        Attribute::Value(pk),
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
        Attribute::KeyType(get_ec_key_type(key_type)?),
    ];
    let private_keys = session
        .find_objects(&private_key_search)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    // TODO: Found more than one key?
    if private_keys.is_empty() {
        return Err(AdacError::CryptoProviderError(
            "Public key not found".to_string(),
        ));
    }

    let public_key_search = vec![
        Attribute::Token(true),
        Attribute::Id(key_id.to_vec()),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(get_ec_key_type(key_type)?),
    ];
    let public_keys = session
        .find_objects(&public_key_search)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    // TODO: Found more than one key?
    if public_keys.is_empty() {
        return Err(AdacError::CryptoProviderError(
            "Public key not found".to_string(),
        ));
    }

    Ok((private_keys[0], public_keys[0]))
}
