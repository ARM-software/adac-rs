// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::{
    self, AdacPublicKey, ec_dsa, ed_448, ed_25519,
    ml_dsa::{KeyConverter, from_spki_mldsa},
};
use adac::{AdacError, CertificateRole, KeyOptions, KeyOptions::*};
use adac::{certificate::AdacCertificate, traits::AdacCryptoProvider};
use base64::prelude::*;
use der::oid::AssociatedOid;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::{PrivateKeyInfo, SecretDocument};
use sec1::DecodeEcPrivateKey;
use std::mem::MaybeUninit;
use std::{fs, path::Path};

pub fn load_certificates<P: AsRef<Path>>(path: P) -> Result<Vec<AdacCertificate>, AdacError> {
    let contents = fs::read_to_string(path).map_err(|e| AdacError::InputOutput(e.to_string()))?;
    read_certificates(contents)
}

pub fn read_certificates(contents: String) -> Result<Vec<AdacCertificate>, AdacError> {
    let mut content = if let Ok(pem) = pem::parse(contents.as_str()) {
        match pem.tag() {
            "ADAC CERTIFICATE CHAIN" => pem.contents().to_vec().clone(),
            _ => return Err(AdacError::Encoding("Unsupported pem tag".to_string())),
        }
    } else {
        BASE64_STANDARD
            .decode(contents)
            .map_err(|e| AdacError::Encoding(e.to_string()))?
    };
    let mut binary = content.as_mut_slice();

    let mut v = Vec::<AdacCertificate>::new();
    while !binary.is_empty() {
        if binary.len() < 8 {
            return Err(AdacError::Encoding(
                "Remaining data too small for TLV entry".to_string(),
            ));
        }
        let (tlv_h, tmp) = binary.split_at_mut(8);
        let tlv_header = unsafe {
            let mut h = MaybeUninit::<adac::AdacTlvHeader>::uninit();
            core::ptr::copy_nonoverlapping(
                tlv_h.as_ptr(),
                h.as_mut_ptr() as *mut u8,
                size_of::<adac::AdacTlvHeader>(),
            );
            h.assume_init()
        };

        // Check if type is ADAC Certificate
        if tlv_header.type_id != 0x201 {
            return Err(AdacError::Encoding("Invalid certificate type".to_string()));
        }
        if tlv_header.length as usize > tmp.len() {
            return Err(AdacError::Encoding(
                "Remaining data too small for TLV size".to_string(),
            ));
        }
        if !tlv_header.length.is_multiple_of(4) {
            return Err(AdacError::Encoding(
                "Certificate size must be a multiple of 4".to_string(),
            ));
        }
        let (crt, left) = tmp.split_at_mut(tlv_header.length as usize);

        match AdacCertificate::from_bytes(crt.to_vec()) {
            Ok(c) => v.push(c),
            Err(e) => return Err(e),
        }
        binary = left;
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
        rsa::pkcs1::ALGORITHM_OID => match pk.private_key.len() {
            1768..=1769 => Rsa3072Sha256,
            2348..=2349 => Rsa4096Sha256,
            _ => return Err(AdacError::InvalidLength),
        },
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
    let mut pubkey = chain[0].get_public_key();

    for (i, current) in chain.iter().enumerate() {
        if i == 0 && current.header().role != CertificateRole::AdacCrtRoleRoot {
            return Err(AdacError::Encoding(
                "First certificate is not Root".to_string(),
            ));
        }

        current.verify(pubkey, crypto)?;
        pubkey = current.get_public_key();
    }
    Ok(())
}

pub fn convert_signature(key_type: KeyOptions, der_sig: &[u8]) -> Result<Vec<u8>, AdacError> {
    Ok(match key_type {
        EcdsaP256Sha256 => {
            let sig = p256::ecdsa::Signature::from_der(der_sig)
                .map_err(|e| AdacError::Encoding(format!("Error decoding signature: {}", e)))?;

            sig.to_bytes().to_vec()
        }
        EcdsaP384Sha384 => {
            let sig = p384::ecdsa::Signature::from_der(der_sig)
                .map_err(|e| AdacError::Encoding(format!("Error decoding signature: {}", e)))?;
            sig.to_bytes().to_vec()
        }
        EcdsaP521Sha512 => {
            let sig = p521::ecdsa::Signature::from_der(der_sig)
                .map_err(|e| AdacError::Encoding(format!("Error decoding signature: {}", e)))?;
            sig.to_bytes().to_vec()
        }
        _ => return Err(AdacError::UnsupportedAlgorithm),
    })
}
