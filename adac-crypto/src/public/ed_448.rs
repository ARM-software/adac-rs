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

fn public_key_from_pkcs8_private_key(
    key: &[u8],
) -> Result<[u8; adac::ED448_PUBLIC_KEY_SIZE_UNPADDED], AdacError> {
    let k = ed448::KeypairBytes::from_pkcs8_der(key)
        .map_err(|e| AdacError::Encoding(format!("Error decoding EdDSA key from PKCS#8: {}", e)))?;
    let signing_key = ed448_goldilocks_plus::SigningKey::try_from(k.secret_key.as_slice())
        .map_err(|e| AdacError::Encoding(e.to_string()))?;
    let public_key = signing_key.verifying_key();

    if let Some(pkcs8_public_key) = k.public_key {
        let pkcs8_public_key = pkcs8_public_key.to_bytes();
        let pkcs8_public_key = ed448_goldilocks_plus::VerifyingKey::from_bytes(&pkcs8_public_key)
            .map_err(|e| AdacError::Encoding(e.to_string()))?;
        if pkcs8_public_key != public_key {
            return Err(AdacError::InconsistentCrypto);
        }
    }

    Ok(public_key.to_bytes())
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
    let pub_key = public_key_from_pkcs8_private_key(key.as_slice())?;
    let vk = ed448_goldilocks_plus::VerifyingKey::from_bytes(&pub_key)
        .map_err(|e| AdacError::Encoding(e.to_string()))?;
    let k = vk
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Error encoding EdDSA key to SPKI: {}", e)))?
        .to_vec();
    Ok(k)
}

pub fn adac_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let pub_key = public_key_from_pkcs8_private_key(key.as_slice())?;
    let mut pk = pub_key.to_vec();
    pk.extend_from_slice(&[0u8; 3]);
    Ok(pk)
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
    use ed448::pkcs8::{DecodePrivateKey, EncodePrivateKey};
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

    #[test]
    fn pkcs8_helpers_reject_mismatched_public_key() {
        let (_, private_key) = crate::utils::load_key(fixture_key_path("Ed448Key-0.pk8")).unwrap();
        let (_, other_private_key) =
            crate::utils::load_key(fixture_key_path("Ed448Key-1.pk8")).unwrap();
        let mut keypair = ed448::KeypairBytes::from_pkcs8_der(&private_key).unwrap();
        keypair.public_key = ed448::KeypairBytes::from_pkcs8_der(&other_private_key)
            .unwrap()
            .public_key;
        let private_key = keypair.to_pkcs8_der().unwrap().as_bytes().to_vec();

        assert!(matches!(
            adac_from_pkcs8(&private_key),
            Err(AdacError::InconsistentCrypto)
        ));
    }
}
