// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::{AdacError, KeyOptions};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use pkcs8::PrivateKeyInfoRef;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use sha2::Digest;
use zeroize::Zeroizing;

fn validate_private_key_size(
    key_type: KeyOptions,
    key: &rsa::RsaPrivateKey,
) -> Result<(), AdacError> {
    adac::validate_rsa_modulus_bits(key_type, key.n().bits() as usize)?;
    adac::validate_rsa_public_exponent(&key.e_bytes())
}

pub fn generate_keypair(
    session: &Session,
    key_type: KeyOptions,
) -> Result<(ObjectHandle, ObjectHandle), AdacError> {
    let public_exponent = adac::RSA_PUBLIC_EXPONENT.to_vec();
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
    key: Zeroizing<Vec<u8>>,
) -> Result<(String, Vec<u8>, Vec<u8>, ObjectHandle, ObjectHandle), AdacError> {
    let pk = PrivateKeyInfoRef::try_from(key.as_slice())
        .map_err(|e| AdacError::Encoding(e.to_string()))?;

    if pk.algorithm.oid != adac_crypto::RSA_OID {
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
        Attribute::PublicExponent(pubk.e_bytes().into_vec()),
        Attribute::Modulus(pubk.n_bytes().into_vec()),
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
        Attribute::PublicExponent(pubk.e_bytes().into_vec()),
        Attribute::Modulus(pubk.n_bytes().into_vec()),
        Attribute::PrivateExponent(pk.d().to_be_bytes_trimmed_vartime().into_vec()),
        Attribute::Label(kid.clone().into_bytes()),
        Attribute::Id(key_id.to_vec()),
    ];

    if pk.primes().len() >= 2
        && let (Some(dp), Some(dq), Some(qinv)) = (pk.dp(), pk.dq(), pk.qinv())
    {
        let coefficient = qinv.retrieve();
        let mut crt_template = vec![
            Attribute::Prime1(pk.primes()[0].to_be_bytes_trimmed_vartime().into_vec()),
            Attribute::Prime2(pk.primes()[1].to_be_bytes_trimmed_vartime().into_vec()),
            Attribute::Exponent1(dp.to_be_bytes_trimmed_vartime().into_vec()),
            Attribute::Exponent2(dq.to_be_bytes_trimmed_vartime().into_vec()),
            Attribute::Coefficient(coefficient.to_be_bytes_trimmed_vartime().into_vec()),
        ];
        private_key_template.append(&mut crt_template);
    }

    let private = super::create_private_object(session, public, &mut private_key_template)?;

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
