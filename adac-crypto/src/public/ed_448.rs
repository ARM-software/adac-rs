// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::AdacPublicKey;
use adac::{AdacError, KeyOptions::Ed448Shake256};
use der::{Decode, SliceReader};
use ed448::pkcs8::DecodePrivateKey;
use spki::{DecodePublicKey, EncodePublicKey};

fn padded_adac_public_key(public_key: &[u8]) -> Result<Vec<u8>, AdacError> {
    if public_key.len() != adac::ED448_PUBLIC_KEY_SIZE_UNPADDED {
        return Err(AdacError::InvalidLength);
    }

    let mut adac = public_key.to_vec();
    adac.extend_from_slice(
        &[0u8; adac::ED448_PUBLIC_KEY_SIZE - adac::ED448_PUBLIC_KEY_SIZE_UNPADDED],
    );
    Ok(adac)
}

pub fn from_adac(adac: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let adac_public_key = adac::validate_public_key_padding(Ed448Shake256, adac)?;
    let mut raw = [0u8; adac::ED448_PUBLIC_KEY_SIZE_UNPADDED];
    raw.copy_from_slice(adac_public_key);
    let pub_key = ed448_goldilocks_plus::PublicKeyBytes(raw);
    let spki = pub_key
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Encoding public key: {}", e)))?
        .to_vec();

    Ok(AdacPublicKey {
        key_type: Ed448Shake256,
        spki,
        adac: adac.to_vec(),
        oid: ed448_goldilocks_plus::ALGORITHM_OID.as_bytes().to_vec(),
        curve: None,
    })
}

pub fn from_spki(spki: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let mut sr = SliceReader::new(spki)
        .map_err(|e| AdacError::Encoding(format!("Internal Error: {}", e)))?;
    let pki = spki::SubjectPublicKeyInfo::decode(&mut sr)
        .map_err(|e| AdacError::Encoding(format!("Decoding SPKI for Elliptic Curve: {}", e)))?;
    let mut adac = ed448_goldilocks_plus::VerifyingKey::try_from(pki)
        .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?
        .to_bytes()
        .to_vec();
    adac.append(&mut vec![0u8; 3]);

    Ok(AdacPublicKey {
        key_type: Ed448Shake256,
        spki: spki.to_vec(),
        adac,
        oid: ed448_goldilocks_plus::ALGORITHM_OID.as_bytes().to_vec(),
        curve: None,
    })
}

pub fn spki_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = ed448::KeypairBytes::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding EdDSA key from PKCS#8: {}", e)))?;
    if let Some(pub_key) = k.public_key {
        let pub_key = pub_key.to_bytes();
        let vk = ed448_goldilocks_plus::VerifyingKey::from_bytes(&pub_key)
            .map_err(|e| AdacError::Encoding(e.to_string()))?;
        let k = vk
            .to_public_key_der()
            .map_err(|e| AdacError::Encoding(format!("Error encoding EdDSA key to SPKI: {}", e)))?
            .to_vec();
        Ok(k)
    } else {
        Err(AdacError::InconsistentCrypto)
    }
}

pub fn adac_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = ed448::KeypairBytes::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding EdDSA key from PKCS#8: {}", e)))?;
    if let Some(pub_key) = k.public_key {
        let pub_key = pub_key.to_bytes();
        let mut pk = pub_key.to_vec();
        pk.extend_from_slice(&[0u8; 3]);
        Ok(pk)
    } else {
        Err(AdacError::InconsistentCrypto)
    }
}

pub fn get_adac_from_spki(public_key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = ed448_goldilocks_plus::VerifyingKey::from_public_key_der(public_key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding EdDSA key from SPKI: {}", e)))?
        .to_bytes()
        .to_vec();
    padded_adac_public_key(&k)
}

pub fn get_spki_from_ec_point(point: &[u8]) -> Result<Vec<u8>, AdacError> {
    let p: [u8; adac::ED448_PUBLIC_KEY_SIZE_UNPADDED] = point
        .try_into()
        .map_err(|_| AdacError::InconsistentCrypto)?;
    let adac = padded_adac_public_key(p.as_slice())?;
    Ok(from_adac(adac.as_slice())?.get_spki().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_key_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../adac-tests/resources/keys")
            .join(name)
    }

    #[test]
    fn get_adac_from_spki_returns_canonical_padded_key() {
        let (_, private_key) = crate::utils::load_key(fixture_key_path("Ed448Key-0.pk8")).unwrap();
        let spki = spki_from_pkcs8(&private_key).unwrap();

        let public_key = get_adac_from_spki(&spki).unwrap();

        assert_eq!(public_key.len(), adac::ED448_PUBLIC_KEY_SIZE);
        assert_eq!(
            &public_key[adac::ED448_PUBLIC_KEY_SIZE_UNPADDED..],
            &[0u8; adac::ED448_PUBLIC_KEY_SIZE - adac::ED448_PUBLIC_KEY_SIZE_UNPADDED]
        );
    }

    #[test]
    fn from_adac_rejects_nonzero_padding() {
        let (_, private_key) = crate::utils::load_key(fixture_key_path("Ed448Key-0.pk8")).unwrap();
        let mut public_key = adac_from_pkcs8(&private_key).unwrap();
        public_key[adac::ED448_PUBLIC_KEY_SIZE_UNPADDED] = 1;

        assert!(matches!(
            from_adac(&public_key),
            Err(AdacError::Encoding(message)) if message == "Invalid public key padding"
        ));
    }
}
