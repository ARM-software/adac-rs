// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::AdacError;
use digest::{ExtendableOutput, Update};
use ed448::pkcs8::DecodePrivateKey;
use ed25519::pkcs8::EncodePublicKey;

pub fn load_key(key: &[u8]) -> Result<([u8; 57], Option<[u8; 57]>, Option<Vec<u8>>), AdacError> {
    let k = ed448::KeypairBytes::from_pkcs8_der(key)
        .map_err(|e| AdacError::Encoding(format!("Error decoding Ed448 key from PKCS#8: {}", e)))?;
    let (pk, spki) = if let Some(pub_key) = k.public_key {
        let pub_key = pub_key.to_bytes();
        let vk = ed448_goldilocks_plus::VerifyingKey::from_bytes(&pub_key)
            .map_err(|e| AdacError::Encoding(e.to_string()))?;
        let pk = ed448_goldilocks_plus::PublicKeyBytes::from(vk);
        let spki = pk
            .to_public_key_der()
            .map_err(|e| AdacError::Encoding(e.to_string()))?
            .to_vec();
        (Some(pk.0), Some(spki))
    } else {
        (None, None)
    };

    Ok((k.secret_key, pk, spki))
}

pub fn shake256_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = shake::Shake256::default();
    hasher.update(data);
    let mut h = vec![0u8; 64];
    hasher.finalize_xof_into(&mut h);
    h
}
