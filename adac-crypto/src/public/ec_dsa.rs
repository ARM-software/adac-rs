// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::AdacPublicKey;
use adac::{AdacError, KeyOptions, KeyOptions::*};
use der::asn1::{BitString, ObjectIdentifier};
use der::oid::AssociatedOid;
use der::{Decode, Encode, SliceReader};
use elliptic_curve::pkcs8::DecodePrivateKey;
use elliptic_curve::{
    AffinePoint, Curve, CurveArithmetic, PublicKey, SecretKey,
    point::PointCompression,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point, ValidatePublicKey},
};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use spki::{DecodePublicKey, EncodePublicKey, SubjectPublicKeyInfo};

fn adac_from_uncompressed_sec1(sec1: &[u8]) -> Result<Vec<u8>, AdacError> {
    let (prefix, adac) = sec1.split_first().ok_or(AdacError::InvalidLength)?;
    if *prefix != 0x04 {
        return Err(AdacError::Encoding(
            "Expected uncompressed SEC1 public key".to_string(),
        ));
    }
    if adac.is_empty() {
        return Err(AdacError::InvalidLength);
    }
    Ok(adac.to_vec())
}

pub trait CurveAbstraction {
    type C: AssociatedOid + CurveArithmetic + PointCompression;

    const NAME: &'static str;

    fn from_sec1_bytes(sec1: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), AdacError>
    where
        <Self::C as Curve>::FieldBytesSize: ModulusSize,
        <Self::C as CurveArithmetic>::AffinePoint: FromSec1Point<Self::C>,
        <Self::C as CurveArithmetic>::AffinePoint: ToSec1Point<Self::C>,
    {
        let spki = PublicKey::<Self::C>::from_sec1_bytes(sec1)
            .map_err(|e| {
                AdacError::Encoding(format!(
                    "Decoding {} public-key from SEC1: {}",
                    Self::NAME,
                    e
                ))
            })?
            .to_public_key_der()
            .map_err(|e| AdacError::Encoding(format!("Encoding to SPKI: {}", e)))?
            .to_vec();
        Ok((spki, Some(Self::C::OID.to_der().unwrap())))
    }

    fn from_spki(spki: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>), AdacError>
    where
        <Self::C as Curve>::FieldBytesSize: ModulusSize,
        <Self::C as CurveArithmetic>::AffinePoint: FromSec1Point<Self::C>,
        <Self::C as CurveArithmetic>::AffinePoint: ToSec1Point<Self::C>,
    {
        let spki = PublicKey::<Self::C>::from_public_key_der(spki)
            .map_err(|e| AdacError::Encoding(format!("Decoding {} SPKI: {}", Self::NAME, e)))?;
        let sec1 = spki.to_sec1_bytes();
        let adac = adac_from_uncompressed_sec1(sec1.as_ref())?;
        let spki = spki
            .to_public_key_der()
            .map_err(|e| AdacError::Encoding(format!("Re-encoding {} SPKI: {}", Self::NAME, e)))?
            .to_vec();
        Ok((spki, adac, Some(Self::C::OID.to_der().unwrap())))
    }
}

impl CurveAbstraction for p256::NistP256 {
    type C = p256::NistP256;
    const NAME: &'static str = "P-256";
}

impl CurveAbstraction for p384::NistP384 {
    type C = p384::NistP384;
    const NAME: &'static str = "P-384";
}

impl CurveAbstraction for p521::NistP521 {
    type C = p521::NistP521;
    const NAME: &'static str = "P-521";
}

pub fn from_adac(key_type: KeyOptions, adac: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(adac);
    from_sec1(key_type, sec1.as_slice())
}

pub fn from_sec1(key_type: KeyOptions, sec1: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let (spki, curve) = match key_type {
        EcdsaP256Sha256 => NistP256::from_sec1_bytes(sec1)?,
        EcdsaP384Sha384 => NistP384::from_sec1_bytes(sec1)?,
        EcdsaP521Sha512 => NistP521::from_sec1_bytes(sec1)?,
        _ => return Err(AdacError::InconsistentCrypto),
    };
    let adac = adac_from_uncompressed_sec1(sec1)?;

    Ok(AdacPublicKey {
        key_type,
        spki,
        adac,
        oid: elliptic_curve::ALGORITHM_OID.to_der().unwrap(),
        curve,
    })
}

pub fn from_spki(spki: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let mut sr = SliceReader::new(spki)
        .map_err(|e| AdacError::Encoding(format!("Internal Error: {}", e)))?;
    let pki: SubjectPublicKeyInfo<ObjectIdentifier, BitString> =
        spki::SubjectPublicKeyInfo::decode(&mut sr)
            .map_err(|e| AdacError::Encoding(format!("Decoding SPKI for Elliptic Curve: {}", e)))?;

    let curve = pki
        .algorithm
        .parameters
        .ok_or(AdacError::Encoding("Missing curve OID".to_string()))?;
    let oid = elliptic_curve::ALGORITHM_OID.to_der().unwrap();
    let ((spki, adac, curve), key_type) = match curve {
        NistP256::OID => (NistP256::from_spki(spki)?, EcdsaP256Sha256),
        NistP384::OID => (NistP384::from_spki(spki)?, EcdsaP384Sha384),
        NistP521::OID => (NistP521::from_spki(spki)?, EcdsaP521Sha512),
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };
    Ok(AdacPublicKey {
        key_type,
        spki,
        adac,
        oid,
        curve,
    })
}

pub fn get_adac_from_spki<C>(public_key: &Vec<u8>) -> Result<Vec<u8>, AdacError>
where
    C: Curve + CurveArithmetic + AssociatedOid + PointCompression,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let k = PublicKey::<C>::from_public_key_der(public_key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding ECDSA key from SPKI: {}", e)))?
        .to_sec1_bytes();
    adac_from_uncompressed_sec1(k.as_ref())
}

pub fn spki_from_pkcs8<C>(key: &Vec<u8>) -> Result<Vec<u8>, AdacError>
where
    C: Curve + CurveArithmetic + AssociatedOid + ValidatePublicKey + PointCompression,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let k = SecretKey::<C>::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding ECDSA key from PKCS#8: {}", e)))?
        .public_key()
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Error encoding ECDSA key to SPKI: {}", e)))?
        .to_vec();
    Ok(k)
}

pub fn adac_from_pkcs8<C>(key: &Vec<u8>) -> Result<Vec<u8>, AdacError>
where
    C: Curve + CurveArithmetic + AssociatedOid + ValidatePublicKey + PointCompression,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let k = SecretKey::<C>::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding ECDSA key from PKCS#8: {}", e)))?
        .public_key()
        .to_sec1_bytes();
    adac_from_uncompressed_sec1(k.as_ref())
}
