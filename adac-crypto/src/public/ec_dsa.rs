// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::AdacPublicKey;
use adac::{AdacError, KeyOptions, KeyOptions::*};
use der::asn1::{BitString, ObjectIdentifier};
use der::oid::AssociatedOid;
use der::{Decode, Encode, SliceReader};
use elliptic_curve::{
    AffinePoint, Curve, CurveArithmetic, JwkParameters, PublicKey, SecretKey,
    point::PointCompression,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint, ValidatePublicKey},
};
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;
use pkcs8::DecodePrivateKey;
use spki::{DecodePublicKey, EncodePublicKey, SubjectPublicKeyInfo};
use std::ops::Deref;

pub trait CurveAbstraction {
    type C: AssociatedOid + JwkParameters + CurveArithmetic + PointCompression;

    fn from_sec1_bytes(sec1: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), AdacError>
    where
        <Self::C as Curve>::FieldBytesSize: ModulusSize,
        <Self::C as CurveArithmetic>::AffinePoint: FromEncodedPoint<Self::C>,
        <Self::C as CurveArithmetic>::AffinePoint: ToEncodedPoint<Self::C>,
    {
        let spki = PublicKey::<Self::C>::from_sec1_bytes(sec1)
            .map_err(|e| {
                AdacError::Encoding(format!(
                    "Decoding {} public-key from SEC1: {}",
                    Self::C::CRV,
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
        <Self::C as CurveArithmetic>::AffinePoint: FromEncodedPoint<Self::C>,
        <Self::C as CurveArithmetic>::AffinePoint: ToEncodedPoint<Self::C>,
    {
        let spki = PublicKey::<Self::C>::from_public_key_der(spki)
            .map_err(|e| AdacError::Encoding(format!("Decoding {} SPKI: {}", Self::C::CRV, e)))?;
        let adac = spki.to_sec1_bytes()[1..].to_vec();
        let spki = spki
            .to_public_key_der()
            .map_err(|e| AdacError::Encoding(format!("Re-encoding {} SPKI: {}", Self::C::CRV, e)))?
            .to_vec();
        Ok((spki, adac, Some(Self::C::OID.to_der().unwrap())))
    }
}

impl CurveAbstraction for p256::NistP256 {
    type C = p256::NistP256;
}

impl CurveAbstraction for p384::NistP384 {
    type C = p384::NistP384;
}

impl CurveAbstraction for p521::NistP521 {
    type C = p521::NistP521;
}

pub fn from_adac(key_type: KeyOptions, adac: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(adac);
    from_sec1(key_type, sec1.as_slice())
}

pub fn from_sec1(key_type: KeyOptions, sec1: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let adac = sec1[1..].to_vec();
    let (spki, curve) = match key_type {
        EcdsaP256Sha256 => NistP256::from_sec1_bytes(sec1)?,
        EcdsaP384Sha384 => NistP384::from_sec1_bytes(sec1)?,
        EcdsaP521Sha512 => NistP521::from_sec1_bytes(sec1)?,
        _ => return Err(AdacError::InconsistentCrypto),
    };

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
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let k = PublicKey::<C>::from_public_key_der(public_key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding ECDSA key from SPKI: {}", e)))?
        .to_sec1_bytes()
        .deref()[1..]
        .to_vec();
    Ok(k)
}

pub fn spki_from_pkcs8<C>(key: &Vec<u8>) -> Result<Vec<u8>, AdacError>
where
    C: Curve + CurveArithmetic + AssociatedOid + ValidatePublicKey + PointCompression,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
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
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    <C as Curve>::FieldBytesSize: ModulusSize,
{
    let k = SecretKey::<C>::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding ECDSA key from PKCS#8: {}", e)))?
        .public_key()
        .to_sec1_bytes()
        .deref()[1..]
        .to_vec();
    Ok(k)
}
