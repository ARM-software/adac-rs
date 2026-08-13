// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::{
    self, AdacPublicKey, ec_dsa, ed_448, ed_25519,
    ml_dsa::{KeyConverter, from_spki_mldsa},
};
use adac::{AdacError, KeyOptions, KeyOptions::*};
use adac::{certificate::AdacCertificate, traits::AdacCryptoProvider};
use base64::prelude::*;
use der::oid::AssociatedOid;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::{PrivateKeyInfo, SecretDocument};
use rsa::{pkcs8::DecodePrivateKey, traits::PublicKeyParts};
use sec1::DecodeEcPrivateKey;
use std::{fs, path::Path};

pub fn load_certificates<P: AsRef<Path>>(path: P) -> Result<Vec<AdacCertificate>, AdacError> {
    let contents = fs::read_to_string(path).map_err(|e| AdacError::InputOutput(e.to_string()))?;
    read_certificates(contents)
}

pub fn read_certificate_chain_bytes(contents: &str) -> Result<Vec<u8>, AdacError> {
    if let Ok(pem) = pem::parse(contents) {
        match pem.tag() {
            "ADAC CERTIFICATE CHAIN" => Ok(pem.contents().to_vec()),
            _ => Err(AdacError::Encoding("Unsupported pem tag".to_string())),
        }
    } else {
        Ok(BASE64_STANDARD
            .decode(contents)
            .map_err(|e| AdacError::Encoding(e.to_string()))?)
    }
}

pub fn read_certificates(contents: String) -> Result<Vec<AdacCertificate>, AdacError> {
    let content = read_certificate_chain_bytes(contents.as_str())?;

    let mut v = Vec::<AdacCertificate>::new();
    for tlv in adac::parse_tlv_sequence(&content)? {
        // Check if type is ADAC Certificate
        let type_id = tlv.header.type_id;
        if type_id != 0x201 {
            return Err(AdacError::Encoding("Invalid certificate type".to_string()));
        }

        match AdacCertificate::from_bytes(tlv.value.to_vec()) {
            Ok(c) => v.push(c),
            Err(e) => return Err(e),
        }
    }
    Ok(v)
}

pub fn save_certificates(certificates: &Vec<AdacCertificate>) -> Result<String, AdacError> {
    if certificates.is_empty() {
        return Err(AdacError::Encoding("No certificate".to_string()));
    }

    let mut export = vec![];
    for crt in certificates {
        export.extend_from_slice(adac::tlv_wrap(0x201, crt.to_bytes()).as_slice());
    }
    let pem = pem::Pem::new("ADAC CERTIFICATE CHAIN", export);
    Ok(pem::encode_config(
        &pem,
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    ))
}

pub fn pkcs8_parse_key(k: Vec<u8>) -> Result<(KeyOptions, Vec<u8>), AdacError> {
    let pk =
        PrivateKeyInfo::try_from(k.as_slice()).map_err(|e| AdacError::Encoding(e.to_string()))?;

    let key_type = match pk.algorithm.oid {
        elliptic_curve::ALGORITHM_OID => {
            let curve = pk
                .algorithm
                .parameters_oid()
                .map_err(|e| AdacError::Encoding(e.to_string()))?;
            match curve {
                p256::NistP256::OID => EcdsaP256Sha256,
                p384::NistP384::OID => EcdsaP384Sha384,
                p521::NistP521::OID => EcdsaP521Sha512,
                sm2::Sm2::OID => SmSm2Sm3,
                _ => return Err(AdacError::UnsupportedAlgorithm),
            }
        }
        crate::ML_DSA_44_OID => MlDsa44Sha256,
        crate::ML_DSA_65_OID => MlDsa65Sha384,
        crate::ML_DSA_87_OID => MlDsa87Sha512,
        ed25519::pkcs8::ALGORITHM_OID => Ed25519Sha512,
        crate::ED_448_OID => Ed448Shake256,
        rsa::pkcs1::ALGORITHM_OID => {
            let key = rsa::RsaPrivateKey::from_pkcs8_der(k.as_slice()).map_err(|e| {
                AdacError::Encoding(format!("Error decoding RSA key from PKCS#8: {}", e))
            })?;
            adac::validate_rsa_public_exponent(&key.e().to_bytes_be())?;
            adac::rsa_key_type_from_modulus_bits(key.n().bits())?.0
        }
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };

    Ok((key_type, k))
}

pub fn load_key<P: AsRef<Path>>(path: P) -> Result<(KeyOptions, Vec<u8>), AdacError> {
    let contents = fs::read_to_string(path).map_err(|e| AdacError::InputOutput(e.to_string()))?;
    read_key(contents)
}

pub fn read_key(content: String) -> Result<(KeyOptions, Vec<u8>), AdacError> {
    let pem = pem::parse(content).map_err(|e| AdacError::Encoding(e.to_string()))?;
    match (pem.tag(), pem.contents().to_vec()) {
        ("EC PRIVATE KEY", der) => {
            let sd: SecretDocument = DecodeEcPrivateKey::from_sec1_der(&der).map_err(|e| {
                AdacError::Encoding(format!("Error decoding EC Private Key: {}", e))
            })?;
            pkcs8_parse_key(sd.to_bytes().to_vec())
        }
        ("PRIVATE KEY", der) => pkcs8_parse_key(der),
        (_, _) => Err(AdacError::Encoding("Unsupported pem tag".to_string())),
    }
}

pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<AdacPublicKey, AdacError> {
    let contents = fs::read_to_string(path).map_err(|e| AdacError::InputOutput(e.to_string()))?;
    read_public_key(contents)
}

pub fn read_public_key(contents: String) -> Result<AdacPublicKey, AdacError> {
    let pem = pem::parse(contents).map_err(|e| AdacError::Encoding(e.to_string()))?;
    match (pem.tag(), pem.contents()) {
        ("PUBLIC KEY", der) => AdacPublicKey::from_spki(der),
        (_, _) => Err(AdacError::Encoding("Unsupported pem tag".to_string())),
    }
}

pub fn get_public_key(key_type: KeyOptions, key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
    let k = match key_type {
        EcdsaP256Sha256 => ec_dsa::adac_from_pkcs8::<NistP256>(key)?,
        EcdsaP384Sha384 => ec_dsa::adac_from_pkcs8::<NistP384>(key)?,
        EcdsaP521Sha512 => ec_dsa::adac_from_pkcs8::<NistP521>(key)?,
        Ed25519Sha512 => ed_25519::adac_from_pkcs8(key)?,
        Ed448Shake256 => ed_448::adac_from_pkcs8(key)?,
        MlDsa44Sha256 => KeyConverter::<MlDsa44>::adac_from_pkcs8(key)?,
        MlDsa65Sha384 => KeyConverter::<MlDsa65>::adac_from_pkcs8(key)?,
        MlDsa87Sha512 => KeyConverter::<MlDsa87>::adac_from_pkcs8(key)?,
        Rsa3072Sha256 | Rsa4096Sha256 => public::rsa::adac_from_pkcs8(key)?,
        SmSm2Sm3 => public::sm::adac_from_pkcs8(key)?,
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };
    Ok(k.clone())
}

pub fn convert_public_key(key_type: KeyOptions, public_key: Vec<u8>) -> Result<Vec<u8>, AdacError> {
    Ok(match key_type {
        EcdsaP256Sha256 => ec_dsa::get_adac_from_spki::<NistP256>(&public_key)?,
        EcdsaP384Sha384 => ec_dsa::get_adac_from_spki::<NistP384>(&public_key)?,
        EcdsaP521Sha512 => ec_dsa::get_adac_from_spki::<NistP521>(&public_key)?,
        Ed25519Sha512 => ed_25519::get_adac_from_spki(&public_key)?,
        Ed448Shake256 => ed_448::get_adac_from_spki(&public_key)?,
        MlDsa44Sha256 => from_spki_mldsa::<MlDsa44>(&public_key)?.0,
        MlDsa65Sha384 => from_spki_mldsa::<MlDsa65>(&public_key)?.0,
        MlDsa87Sha512 => from_spki_mldsa::<MlDsa87>(&public_key)?.0,
        Rsa3072Sha256 | Rsa4096Sha256 => public::rsa::get_adac_from_spki(&public_key)?,
        SmSm2Sm3 => public::sm::get_adac_from_spki(&public_key)?,
        _ => return Err(AdacError::UnsupportedAlgorithm),
    })
}

pub fn verify_chain(
    chain: Vec<AdacCertificate>,
    crypto: &dyn AdacCryptoProvider,
) -> Result<(), AdacError> {
    let result = crate::validation::validate_chain(&chain, crypto);
    if let Some(error) = result.first_error() {
        return Err(AdacError::Encoding(error.to_string()));
    }
    Ok(())
}

pub fn convert_signature(key_type: KeyOptions, signature: &[u8]) -> Result<Vec<u8>, AdacError> {
    Ok(match key_type {
        EcdsaP256Sha256 => {
            let sig = p256::ecdsa::Signature::from_der(signature)
                .map_err(|e| AdacError::Encoding(format!("Error decoding signature: {}", e)))?;

            sig.to_bytes().to_vec()
        }
        EcdsaP384Sha384 => {
            let sig = p384::ecdsa::Signature::from_der(signature)
                .map_err(|e| AdacError::Encoding(format!("Error decoding signature: {}", e)))?;
            sig.to_bytes().to_vec()
        }
        EcdsaP521Sha512 => {
            let sig = p521::ecdsa::Signature::from_der(signature)
                .map_err(|e| AdacError::Encoding(format!("Error decoding signature: {}", e)))?;
            sig.to_bytes().to_vec()
        }
        MlDsa44Sha256 => normalize_ml_dsa_signature::<MlDsa44>(
            key_type,
            signature,
            adac::MLDSA_44_SIGNATURE_SIZE,
        )?,
        MlDsa65Sha384 => normalize_ml_dsa_signature::<MlDsa65>(
            key_type,
            signature,
            adac::MLDSA_65_SIGNATURE_SIZE,
        )?,
        MlDsa87Sha512 => normalize_ml_dsa_signature::<MlDsa87>(
            key_type,
            signature,
            adac::MLDSA_87_SIGNATURE_SIZE,
        )?,
        _ => return Err(AdacError::UnsupportedAlgorithm),
    })
}

fn normalize_ml_dsa_signature<P: MlDsaParams>(
    key_type: KeyOptions,
    signature: &[u8],
    padded_size: usize,
) -> Result<Vec<u8>, AdacError> {
    let signature = if signature.len() == padded_size {
        adac::validate_signature_padding(key_type, signature)?
    } else {
        signature
    };

    let signature = ml_dsa::Signature::<P>::try_from(signature)
        .map_err(|e| AdacError::Encoding(format!("Error decoding ML-DSA signature: {}", e)))?;

    let mut normalized = Vec::with_capacity(padded_size);
    normalized.extend_from_slice(&signature.encode());
    normalized.resize(padded_size, 0);
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_signature_rejects_malformed_ml_dsa_signature() {
        let signature = vec![0xff; adac::MLDSA_87_SIGNATURE_UNPADDED];

        assert!(matches!(
            convert_signature(MlDsa87Sha512, &signature),
            Err(AdacError::Encoding(message))
                if message.starts_with("Error decoding ML-DSA signature:")
        ));
    }
}
