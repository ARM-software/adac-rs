// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::public::AdacPublicKey;
use adac::{
    AdacError,
    KeyOptions::{self, *},
};
use hybrid_array::{Array, typenum::U32};
use ml_dsa::pkcs8::der::{self, AnyRef, Encode, Reader, SecretDocument, SliceReader};
use ml_dsa::pkcs8::{self, PrivateKeyInfoRef, spki};
use ml_dsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ml_dsa::signature::Keypair;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams, SigningKey, VerifyingKey};
use std::marker::PhantomData;

// TODO: KeyConverter is only needed until ml-dsa supports the updated IETF standard seed encoding.
type B32 = Array<u8, U32>;
type SeedString<'a> = der::asn1::ContextSpecific<&'a der::asn1::OctetStringRef>;
const SEED_TAG_NUMBER: der::TagNumber = der::TagNumber(0);

pub struct KeyConverter<P: MlDsaParams> {
    /// The seed this signing key was derived from
    seed: B32,
    phantom: PhantomData<P>,
}

impl<P> TryFrom<PrivateKeyInfoRef<'_>> for KeyConverter<P>
where
    P: MlDsaParams,
    P: spki::AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = pkcs8::Error;

    fn try_from(private_key_info: PrivateKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        private_key_info
            .algorithm
            .assert_algorithm_oid(P::ALGORITHM_IDENTIFIER.oid)?;

        let private_key = private_key_info.private_key.as_bytes();
        let seed_bytes = if private_key.len() == 32 {
            private_key
        } else {
            let mut reader = SliceReader::new(private_key)?;
            let seed_string = SeedString::decode_implicit(&mut reader, SEED_TAG_NUMBER)?
                .ok_or(pkcs8::Error::KeyMalformed)?;
            reader.finish()?;
            seed_string.value.as_bytes()
        };

        let seed = Array::try_from(seed_bytes).map_err(|_| pkcs8::Error::KeyMalformed)?;
        Ok(KeyConverter {
            seed,
            phantom: PhantomData::<P>,
        })
    }
}

impl<P> EncodePrivateKey for KeyConverter<P>
where
    P: MlDsaParams,
    P: spki::AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    fn to_pkcs8_der(&self) -> Result<SecretDocument, pkcs8::Error> {
        let seed_der = SeedString {
            tag_mode: ml_dsa::pkcs8::der::TagMode::Implicit,
            tag_number: SEED_TAG_NUMBER,
            value: der::asn1::OctetStringRef::new(&self.seed)?,
        }
        .to_der()?;

        let private_key = der::asn1::OctetStringRef::new(&seed_der)?;
        let private_key_info = PrivateKeyInfoRef::new(P::ALGORITHM_IDENTIFIER, private_key);
        SecretDocument::encode_msg(&private_key_info).map_err(pkcs8::Error::Asn1)
    }
}

impl<P> KeyConverter<P>
where
    P: MlDsaParams,
    P: spki::AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
    KeyConverter<P>: DecodePrivateKey + EncodePrivateKey,
    SigningKey<P>: DecodePrivateKey,
    VerifyingKey<P>: EncodePublicKey,
{
    pub fn fix_pkcs8_der(input: &[u8]) -> Result<Vec<u8>, AdacError> {
        let out = KeyConverter::<P>::from_pkcs8_der(input)
            .map_err(|e| {
                AdacError::Encoding(format!("Error decoding ML-DSA key from PKCS#8: {}", e))
            })?
            .to_pkcs8_der()
            .map_err(|e| {
                AdacError::Encoding(format!("Error re-encoding ML-DSA key to PKCS#8: {}", e))
            })?
            .as_bytes()
            .to_vec();
        Ok(out)
    }

    pub fn adac_from_pkcs8(key: &Vec<u8>) -> Result<Vec<u8>, AdacError> {
        let key = KeyConverter::<P>::fix_pkcs8_der(key.as_slice())?;
        let evk = SigningKey::<P>::from_pkcs8_der(key.as_slice())
            .map_err(|e| {
                AdacError::Encoding(format!("Error decoding ML-DSA key from PKCS#8: {}", e))
            })?
            .verifying_key()
            .encode();
        Ok(evk.to_vec())
    }

    pub fn seed_from_pkcs8(key: &[u8]) -> Result<Vec<u8>, AdacError> {
        let converter = KeyConverter::<P>::from_pkcs8_der(key).map_err(|e| {
            AdacError::Encoding(format!("Error decoding ML-DSA key from PKCS#8: {}", e))
        })?;
        Ok(converter.seed.to_vec())
    }
}

pub fn pkcs8_import_parts(
    key_type: KeyOptions,
    key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), AdacError> {
    let key = key.to_vec();
    let (seed, adac, spki) = match key_type {
        MlDsa44Sha256 => (
            KeyConverter::<MlDsa44>::seed_from_pkcs8(key.as_slice())?,
            KeyConverter::<MlDsa44>::adac_from_pkcs8(&key)?,
            spki_from_pkcs8::<MlDsa44>(&key)?,
        ),
        MlDsa65Sha384 => (
            KeyConverter::<MlDsa65>::seed_from_pkcs8(key.as_slice())?,
            KeyConverter::<MlDsa65>::adac_from_pkcs8(&key)?,
            spki_from_pkcs8::<MlDsa65>(&key)?,
        ),
        MlDsa87Sha512 => (
            KeyConverter::<MlDsa87>::seed_from_pkcs8(key.as_slice())?,
            KeyConverter::<MlDsa87>::adac_from_pkcs8(&key)?,
            spki_from_pkcs8::<MlDsa87>(&key)?,
        ),
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };

    Ok((seed, adac, spki))
}

pub fn from_adac_mldsa<P>(adac: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AdacError>
where
    P: MlDsaParams,
    P: spki::AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
    VerifyingKey<P>: DecodePublicKey + EncodePublicKey,
{
    let vk_bytes = ml_dsa::EncodedVerifyingKey::<P>::try_from(adac)
        .map_err(|e| AdacError::Encoding(format!("Decoding public key: {}", e)))?;
    let vk = ml_dsa::VerifyingKey::<P>::decode(&vk_bytes);
    let spki = vk
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Encoding public key: {}", e)))?
        .to_vec();
    Ok((spki, P::ALGORITHM_IDENTIFIER.to_der().unwrap()))
}

pub fn from_adac(key_type: KeyOptions, adac: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let (spki, oid) = match key_type {
        MlDsa44Sha256 => from_adac_mldsa::<MlDsa44>(adac)?,
        MlDsa65Sha384 => from_adac_mldsa::<MlDsa65>(adac)?,
        MlDsa87Sha512 => from_adac_mldsa::<MlDsa87>(adac)?,
        _ => return Err(AdacError::InconsistentCrypto),
    };
    let adac = adac.to_vec();

    Ok(AdacPublicKey {
        key_type,
        spki,
        adac,
        oid,
        curve: None,
    })
}

pub fn from_spki_mldsa<P>(public_key: &Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), AdacError>
where
    P: MlDsaParams,
    P: spki::AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
    VerifyingKey<P>: DecodePublicKey + EncodePublicKey,
{
    let k = VerifyingKey::<P>::from_public_key_der(public_key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding ML-DSA key from SPKI: {}", e)))?
        .encode()
        .as_slice()
        .to_vec();

    Ok((k, P::ALGORITHM_IDENTIFIER.to_der().unwrap()))
}

pub fn from_spki(key_type: KeyOptions, spki: &[u8]) -> Result<AdacPublicKey, AdacError> {
    let spki = spki.to_vec();
    let (adac, oid) = match key_type {
        MlDsa44Sha256 => from_spki_mldsa::<MlDsa44>(&spki)?,
        MlDsa65Sha384 => from_spki_mldsa::<MlDsa65>(&spki)?,
        MlDsa87Sha512 => from_spki_mldsa::<MlDsa87>(&spki)?,
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };
    Ok(AdacPublicKey {
        key_type,
        spki,
        adac,
        oid,
        curve: None,
    })
}

pub fn spki_from_pkcs8<P>(key: &Vec<u8>) -> Result<Vec<u8>, AdacError>
where
    P: MlDsaParams,
    P: spki::AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
    KeyConverter<P>: DecodePrivateKey + EncodePrivateKey,
    SigningKey<P>: DecodePrivateKey,
    VerifyingKey<P>: EncodePublicKey,
{
    let key = KeyConverter::<P>::fix_pkcs8_der(key.as_slice())?;
    let spki = SigningKey::<P>::from_pkcs8_der(key.as_slice())
        .map_err(|e| AdacError::Encoding(format!("Error decoding ML-DSA key from PKCS#8: {}", e)))?
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| AdacError::Encoding(format!("Error encoding EdDSA key to SPKI: {}", e)))?
        .to_vec();
    Ok(spki)
}
