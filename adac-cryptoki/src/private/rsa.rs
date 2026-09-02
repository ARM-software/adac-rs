// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::{AdacError, KeyOptions};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use elliptic_curve::pkcs8::{EncodePublicKey, PrivateKeyInfo};
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use sha2::Digest;

fn validate_private_key_size(
    key_type: KeyOptions,
    key: &rsa::RsaPrivateKey,
) -> Result<(), AdacError> {
    adac::validate_rsa_modulus_bits(key_type, key.n().bits())
}

pub fn generate_keypair(
    session: &Session,
    key_type: KeyOptions,
) -> Result<(ObjectHandle, ObjectHandle), AdacError> {
    let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
    let modulus_bits = cryptoki::types::Ulong::try_from(adac::rsa_modulus_bits(key_type)?)
        .map_err(|_e| AdacError::InconsistentCrypto)?;

    let public_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::PublicExponent(public_exponent),
        Attribute::ModulusBits(modulus_bits),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Verify(true),
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
            &Mechanism::RsaPkcsKeyPairGen,
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

    if pk.algorithm.oid != rsa::pkcs1::ALGORITHM_OID {
        return Err(AdacError::UnsupportedAlgorithm);
    }

    let pk = rsa::RsaPrivateKey::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(e.to_string()))?;
    validate_private_key_size(key_type, &pk)?;
    let pubk = pk.to_public_key();
    let spki = pubk
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(e.to_string()))?
        .to_vec();

    let key_id = sha2::Sha256::digest(spki.as_slice());
    let kid = base16ct::lower::encode_string(&key_id);

    let public_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::PublicExponent(pubk.e().to_bytes_be()),
        Attribute::Modulus(pubk.n().to_bytes_be()),
        Attribute::Label(kid.clone().into_bytes()),
        Attribute::Id(key_id.to_vec()),
    ];

    let public = session
        .create_object(&public_key_template)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    let mut private_key_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::PublicExponent(pubk.e().to_bytes_be()),
        Attribute::Modulus(pubk.n().to_bytes_be()),
        Attribute::PrivateExponent(pk.d().to_bytes_be()),
        Attribute::Label(kid.clone().into_bytes()),
        Attribute::Id(key_id.to_vec()),
    ];

    if pk.primes().len() >= 2 && pk.dp().is_some() && pk.dq().is_some() && pk.qinv().is_some() {
        let mut crt_template = vec![
            Attribute::Prime1(pk.primes()[0].to_bytes_be()),
            Attribute::Prime2(pk.primes()[1].to_bytes_be()),
            Attribute::Exponent1(pk.dp().unwrap().to_bytes_be()),
            Attribute::Exponent2(pk.dq().unwrap().to_bytes_be()),
            Attribute::Coefficient(pk.qinv().unwrap().to_bytes_be().1),
        ];
        private_key_template.append(&mut crt_template);
    }

    let private = match session.create_object(&private_key_template) {
        Ok(private) => private,
        Err(e) => {
            let e_create = e.to_string();
            if let Err(e_cleanup) = session.destroy_object(public) {
                return Err(AdacError::CryptoProviderError(format!(
                    "Error creating private key object: '{e_create}' and failed to destroy public key object: '{e_cleanup}'",
                )));
            }
            return Err(AdacError::CryptoProviderError(e_create));
        }
    };

    Ok((kid, key_id.to_vec(), spki, private, public))
}

pub fn find_keypair(
    session: &Session,
    key_type: KeyOptions,
    key_id: &[u8],
) -> Result<(ObjectHandle, ObjectHandle), AdacError> {
    adac::rsa_modulus_bits(key_type)?;

    let private_key_search = vec![
        Attribute::Token(true),
        Attribute::Id(key_id.to_vec()),
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::RSA),
    ];
    let private_keys = session
        .find_objects(&private_key_search)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    let private = super::unique_key_object(&private_keys, "private key", key_id)?;

    let public_key_search = vec![
        Attribute::Token(true),
        Attribute::Id(key_id.to_vec()),
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
    ];
    let public_keys = session
        .find_objects(&public_key_search)
        .map_err(|e| AdacError::CryptoProviderError(e.to_string()))?;

    let public = super::unique_key_object(&public_keys, "public key", key_id)?;

    Ok((private, public))
}
