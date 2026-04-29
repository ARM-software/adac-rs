// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public;
use adac::{AdacError, KeyOptions, KeyOptions::*};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectHandle};
use cryptoki::session::Session;
use cryptoki::types::Ulong;
use sha2::Digest;

pub mod ec;
pub mod rsa;

pub fn generate_keypair(
    session: &Session,
    key_type: KeyOptions,
) -> Result<(String, Vec<u8>, Vec<u8>, ObjectHandle, ObjectHandle), AdacError> {
    let (public, private) = match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => {
            ec::generate_ecdsa_keypair(session, key_type)?
        }
        Ed25519Sha512 | Ed448Shake256 => ec::generate_eddsa_keypair(session, key_type)?,
        Rsa3072Sha256 | Rsa4096Sha256 => rsa::generate_keypair(session, key_type)?,
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };

    set_kid(session, key_type, public, private)
}

pub fn import_key(
    session: &Session,
    key_type: KeyOptions,
    key: Vec<u8>,
) -> Result<(String, Vec<u8>, Vec<u8>, ObjectHandle, ObjectHandle), AdacError> {
    match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 | Ed25519Sha512 | Ed448Shake256 => {
            ec::import_key(session, key_type, key)
        }
        Rsa3072Sha256 | Rsa4096Sha256 => rsa::import_key(session, key_type, key),
        _ => Err(AdacError::UnsupportedAlgorithm),
    }
}

pub fn find_keypair(
    session: &Session,
    key_type: KeyOptions,
    key_id: &[u8],
) -> Result<(ObjectHandle, ObjectHandle), AdacError> {
    let (private, public) = match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 | Ed25519Sha512 | Ed448Shake256 => {
            ec::find_keypair(session, key_type, key_id)
        }
        Rsa3072Sha256 | Rsa4096Sha256 => rsa::find_keypair(session, key_type, key_id),
        _ => Err(AdacError::UnsupportedAlgorithm),
    }?;

    // validate_keypair(session, key_type, private, public)?;
    Ok((private, public))
}

pub(crate) fn unique_key_object(
    matches: &[ObjectHandle],
    object_name: &str,
    key_id: &[u8],
) -> Result<ObjectHandle, AdacError> {
    match matches {
        [] => Err(AdacError::CryptoProviderError(format!(
            "PKCS#11 {object_name} with ID '{}' was not found",
            base16ct::lower::encode_string(key_id)
        ))),
        [object] => Ok(*object),
        _ => Err(AdacError::CryptoProviderError(format!(
            "Multiple PKCS#11 {object_name} objects with ID '{}' were found",
            base16ct::lower::encode_string(key_id)
        ))),
    }
}

#[allow(dead_code)]
fn validate_keypair(
    session: &Session,
    key_type: KeyOptions,
    private: ObjectHandle,
    public: ObjectHandle,
) -> Result<(), AdacError> {
    let probe = b"ADAC PKCS#11 key pair consistency check";
    let signature = sign(session, key_type, private, probe)?;
    public::verify(session, key_type, public, probe, signature.as_slice()).map_err(|e| {
        AdacError::CryptoProviderError(format!(
            "PKCS#11 public and private key objects do not form a valid key pair: {e:?}"
        ))
    })
}

pub fn kid_from_public_handle(
    session: &Session,
    key_type: KeyOptions,
    public: ObjectHandle,
) -> Result<(String, Vec<u8>, Vec<u8>), AdacError> {
    let spki = public::load_public_key(session, key_type, public)?;
    let key_id = sha2::Sha256::digest(spki.as_slice()).to_vec();
    let kid = base16ct::lower::encode_string(&key_id);
    Ok((kid, key_id, spki))
}

pub fn set_kid(
    session: &Session,
    key_type: KeyOptions,
    public: ObjectHandle,
    private: ObjectHandle,
) -> Result<(String, Vec<u8>, Vec<u8>, ObjectHandle, ObjectHandle), AdacError> {
    let (kid, key_id, spki) = kid_from_public_handle(session, key_type, public)?;

    let update_attributes = vec![
        Attribute::Label(kid.clone().into_bytes()),
        Attribute::Id(key_id.to_vec()),
    ];

    session
        .update_attributes(public, &update_attributes)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;
    session
        .update_attributes(private, &update_attributes)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    Ok((kid, key_id, spki, private, public))
}

pub fn sign(
    session: &Session,
    key_type: KeyOptions,
    handle: ObjectHandle,
    data: &[u8],
) -> Result<Vec<u8>, AdacError> {
    let signature = match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => {
            let hash = crate::hash(session, key_type, data)?;
            session
                .sign(&Mechanism::Ecdsa, handle, hash.as_slice())
                .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?
        }
        Rsa3072Sha256 | Rsa4096Sha256 => session
            .sign(
                &Mechanism::Sha256RsaPkcsPss(PkcsPssParams {
                    hash_alg: MechanismType::SHA256,
                    mgf: PkcsMgfType::MGF1_SHA256,
                    s_len: Ulong::from(32),
                }),
                handle,
                data,
            )
            .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?,
        Ed25519Sha512 => {
            let hash = crate::hash(session, key_type, data)?;
            let params = EddsaParams::new(EddsaSignatureScheme::Ed25519ph(&[]));
            session
                .sign(&Mechanism::Eddsa(params), handle, hash.as_slice())
                .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?
        }
        Ed448Shake256 => {
            let hash = crate::hash(session, key_type, data)?;
            let params = EddsaParams::new(EddsaSignatureScheme::Ed448ph(&[]));
            let mut sig = session
                .sign(&Mechanism::Eddsa(params), handle, hash.as_slice())
                .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;
            sig.append(&mut vec![0u8; 2]);
            sig
        }
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };
    Ok(signature)
}
