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
pub mod mldsa;
pub mod rsa;

pub fn generate_keypair(
    session: &Session,
    key_type: KeyOptions,
) -> Result<(String, Vec<u8>, Vec<u8>, ObjectHandle, ObjectHandle), AdacError> {
    let (public, private) = match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => {
            ec::generate_ecdsa_keypair(session, key_type)?
        }
        MlDsa44Sha256 | MlDsa65Sha384 | MlDsa87Sha512 => {
            mldsa::generate_keypair(session, key_type)?
        }
        Ed25519Sha512 | Ed448Shake256 => ec::generate_eddsa_keypair(session, key_type)?,
        Rsa3072Sha256 | Rsa4096Sha256 => rsa::generate_keypair(session, key_type)?,
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };

    match set_kid(session, key_type, public, private) {
        Ok(keypair) => Ok(keypair),
        Err(error) => Err(destroy_keypair_after_error(session, private, public, error)),
    }
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
        MlDsa44Sha256 | MlDsa65Sha384 | MlDsa87Sha512 => mldsa::import_key(session, key_type, key),
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
        MlDsa44Sha256 | MlDsa65Sha384 | MlDsa87Sha512 => {
            mldsa::find_keypair(session, key_type, key_id)
        }
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

pub(crate) fn create_private_object(
    session: &Session,
    public: ObjectHandle,
    private_key_template: &[Attribute],
) -> Result<ObjectHandle, AdacError> {
    match session.create_object(private_key_template) {
        Ok(private) => Ok(private),
        Err(error) => {
            let primary = error.to_string();
            if let Err(cleanup) = session.destroy_object(public) {
                return Err(AdacError::CryptoProviderError(format!(
                    "Error creating private key object: '{primary}'; failed to destroy public key object: '{cleanup}'"
                )));
            }
            Err(AdacError::CryptoProviderError(primary))
        }
    }
}

fn destroy_keypair_after_error(
    session: &Session,
    private: ObjectHandle,
    public: ObjectHandle,
    error: AdacError,
) -> AdacError {
    let mut cleanup_errors = Vec::new();
    if let Err(cleanup) = session.destroy_object(private) {
        cleanup_errors.push(format!("private key: {cleanup}"));
    }
    if let Err(cleanup) = session.destroy_object(public) {
        cleanup_errors.push(format!("public key: {cleanup}"));
    }

    if cleanup_errors.is_empty() {
        error
    } else {
        AdacError::CryptoProviderError(format!(
            "Key pair finalization failed: {error:?}; cleanup also failed for {}",
            cleanup_errors.join(", ")
        ))
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
            let params = EddsaParams::new(EddsaSignatureScheme::Ed25519ph(&[]));
            session
                .sign(&Mechanism::Eddsa(params), handle, data)
                .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?
        }
        Ed448Shake256 => {
            let params = EddsaParams::new(EddsaSignatureScheme::Ed448ph(&[]));
            let mut sig = session
                .sign(&Mechanism::Eddsa(params), handle, data)
                .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;
            sig.append(&mut vec![0u8; 2]);
            sig
        }
        MlDsa44Sha256 | MlDsa65Sha384 | MlDsa87Sha512 => {
            let params = cryptoki::mechanism::dsa::SignAdditionalContext::new(
                cryptoki::mechanism::dsa::HedgeType::Preferred,
                None,
            );
            let sig = session
                .sign(&Mechanism::MlDsa(params), handle, data)
                .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;
            public::mldsa::pad_signature(key_type, sig)?
        }
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };
    Ok(signature)
}
