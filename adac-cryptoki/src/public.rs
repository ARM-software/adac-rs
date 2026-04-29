// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::KeyOptions::{
    EcdsaP256Sha256, EcdsaP384Sha384, EcdsaP521Sha512, Ed448Shake256, Ed25519Sha512, MlDsa44Sha256,
    MlDsa65Sha384, MlDsa87Sha512, Rsa3072Sha256, Rsa4096Sha256,
};
use adac::{AdacError, KeyOptions};
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;
use der::{Decode, SliceReader};

pub mod ec;
pub mod mldsa;
pub mod rsa;

pub fn load_public_key(
    session: &Session,
    key_type: KeyOptions,
    key_handle: ObjectHandle,
) -> Result<Vec<u8>, AdacError> {
    match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 | Ed25519Sha512 | Ed448Shake256 => {
            ec::load_public_key(session, key_type, key_handle)
        }
        Rsa3072Sha256 | Rsa4096Sha256 => rsa::load_public_key(session, key_type, key_handle),
        MlDsa44Sha256 | MlDsa65Sha384 | MlDsa87Sha512 => {
            mldsa::load_public_key(session, key_type, key_handle)
        }
        _ => Err(AdacError::UnsupportedAlgorithm),
    }
}

pub fn import_public_key(
    session: &Session,
    key_type: KeyOptions,
    public_key: &[u8],
) -> Result<ObjectHandle, AdacError> {
    match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 | Ed25519Sha512 | Ed448Shake256 => {
            ec::import_public_key(session, key_type, public_key)
        }
        Rsa3072Sha256 | Rsa4096Sha256 => rsa::import_public_key(session, key_type, public_key),
        MlDsa44Sha256 | MlDsa65Sha384 | MlDsa87Sha512 => {
            mldsa::import_public_key(session, key_type, public_key)
        }
        _ => Err(AdacError::UnsupportedAlgorithm),
    }
}

pub fn verify(
    session: &Session,
    key_type: KeyOptions,
    handle: ObjectHandle,
    data: &[u8],
    signature: &[u8],
) -> Result<(), AdacError> {
    let signature = adac::validate_signature_padding(key_type, signature)?;

    match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 | Ed25519Sha512 | Ed448Shake256 => {
            ec::verify(session, key_type, handle, data, signature)
        }
        Rsa3072Sha256 | Rsa4096Sha256 => rsa::verify(session, key_type, handle, data, signature),
        MlDsa44Sha256 | MlDsa65Sha384 | MlDsa87Sha512 => {
            mldsa::verify(session, key_type, handle, data, signature)
        }
        _ => Err(AdacError::UnsupportedAlgorithm),
    }
}

fn from_octet_string(octet_string: &[u8]) -> Result<Vec<u8>, AdacError> {
    let sr = &mut SliceReader::new(octet_string)
        .map_err(|e| AdacError::Encoding(format!("SliceReader new failed: {}", e)))?;
    Ok(der::asn1::OctetString::decode(sr)
        .map_err(|e| AdacError::Encoding(format!("Decoding from SEC1 format failed: {}", e)))?
        .as_ref()
        .to_vec())
}

pub fn get_sec1_from_ec_point(key_type: KeyOptions, point: &[u8]) -> Result<Vec<u8>, AdacError> {
    Ok(match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 => from_octet_string(point)?,
        Ed25519Sha512 => {
            if point.len() > adac::ED25519_PUBLIC_KEY_SIZE {
                from_octet_string(point)?
            } else {
                point.to_vec()
            }
        }
        Ed448Shake256 => {
            if point.len() > adac::ED448_PUBLIC_KEY_SIZE_UNPADDED {
                from_octet_string(point)?
            } else {
                point.to_vec()
            }
        }
        _ => return Err(AdacError::InconsistentCrypto),
    })
}
