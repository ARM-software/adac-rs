// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use core::mem::size_of;

pub mod certificate;
pub mod token;
pub mod traits;

#[derive(Debug, Clone)]
pub enum AdacError {
    InvalidLength,
    InconsistentCrypto,
    InconsistentVersion,
    InputOutput(String),
    UnsupportedAlgorithm,
    CryptoProviderError(String),
    Encoding(String),
    InvalidSignature,
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum KeyOptions {
    /** EC key using P-256 curve, ECDSA signature with SHA-256 */
    EcdsaP256Sha256 = 0x01,
    /** EC key using P-521 curve, ECDSA signature with SHA-512 */
    EcdsaP521Sha512 = 0x02,
    /** 3072-bit RSA key, RSA signature with SHA-256 */
    Rsa3072Sha256 = 0x03,
    /** 4096-bit RSA key, RSA signature with SHA-256 */
    Rsa4096Sha256 = 0x04,
    /** EC key using Curve25519, EdDSA signature with SHA-512 */
    Ed25519Sha512 = 0x05,
    /** EC key using Curve448, EdDSA signature with SHAKE-256 */
    Ed448Shake256 = 0x06,
    /** EC key using SM2, ECDSA/SM signature with SM3 */
    SmSm2Sm3 = 0x07,
    /** AES-128 key, CMAC MAC */
    CmacAes = 0x08,
    /** 256-bit key, HMAC-SHA-256 MAC */
    HmacSha256 = 0x09,
    /** EC key using P-384 curve, ECDSA signature with SHA-384 */
    EcdsaP384Sha384 = 0x0A,
    /* ML-DSA-44 with SHA-256 */
    MlDsa44Sha256 = 0x0B,
    /* ML-DSA-65 with SHA-384 */
    MlDsa65Sha384 = 0x0C,
    /* ML-DSA-87 with SHA-512 */
    MlDsa87Sha512 = 0x0D,
}

impl TryFrom<u8> for KeyOptions {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::EcdsaP256Sha256 as u8 => Ok(Self::EcdsaP256Sha256),
            x if x == Self::EcdsaP521Sha512 as u8 => Ok(Self::EcdsaP521Sha512),
            x if x == Self::Rsa3072Sha256 as u8 => Ok(Self::Rsa3072Sha256),
            x if x == Self::Rsa4096Sha256 as u8 => Ok(Self::Rsa4096Sha256),
            x if x == Self::Ed25519Sha512 as u8 => Ok(Self::Ed25519Sha512),
            x if x == Self::Ed448Shake256 as u8 => Ok(Self::Ed448Shake256),
            x if x == Self::SmSm2Sm3 as u8 => Ok(Self::SmSm2Sm3),
            x if x == Self::CmacAes as u8 => Ok(Self::CmacAes),
            x if x == Self::HmacSha256 as u8 => Ok(Self::HmacSha256),
            x if x == Self::EcdsaP384Sha384 as u8 => Ok(Self::EcdsaP384Sha384),
            x if x == Self::MlDsa44Sha256 as u8 => Ok(Self::MlDsa44Sha256),
            x if x == Self::MlDsa65Sha384 as u8 => Ok(Self::MlDsa65Sha384),
            x if x == Self::MlDsa87Sha512 as u8 => Ok(Self::MlDsa87Sha512),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(C, packed)]
pub struct AdacVersion {
    pub major: u8,
    pub minor: u8,
}

/** Certificate role */
#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum CertificateRole {
    /* Root Certification Authority Certificate */
    AdacCrtRoleRoot = 0x01,
    /* Intermediate Certification Authority Certificate */
    AdacCrtRoleInt = 0x02,
    /* Leaf Certificate */
    AdacCrtRoleLeaf = 0x03,
}

impl TryFrom<u8> for CertificateRole {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::AdacCrtRoleRoot as u8 => Ok(Self::AdacCrtRoleRoot),
            x if x == Self::AdacCrtRoleInt as u8 => Ok(Self::AdacCrtRoleInt),
            x if x == Self::AdacCrtRoleLeaf as u8 => Ok(Self::AdacCrtRoleLeaf),
            _ => Err(()),
        }
    }
}

/** Certificate role */
#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum CertificateUsage {
    /* No Specific Usage */
    AdacUsageNeutral = 0x00,
    /* Authentication only */
    AdacUsageStandard = 0x01,
    /* RMA */
    AdacUsageRma = 0x02,
}

impl TryFrom<u8> for CertificateUsage {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::AdacUsageNeutral as u8 => Ok(Self::AdacUsageNeutral),
            x if x == Self::AdacUsageStandard as u8 => Ok(Self::AdacUsageStandard),
            x if x == Self::AdacUsageRma as u8 => Ok(Self::AdacUsageRma),
            _ => Err(()),
        }
    }
}

/* Certificate header */
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct CertificateHeader {
    pub format_version: AdacVersion,
    pub signature_type: KeyOptions,
    pub key_type: KeyOptions,
    pub role: CertificateRole,
    pub usage: CertificateUsage,
    // Must be set to zero if version 1.0.
    pub policies: u16,
    pub lifecycle: u16,
    pub oem_constraint: u16,
    pub extensions_bytes: u32,
    pub soc_class: u32,
    pub soc_id: [u8; 16],
    pub permissions_mask: [u8; 16],
}

impl Default for CertificateHeader {
    fn default() -> Self {
        Self {
            format_version: AdacVersion { major: 1, minor: 0 },
            signature_type: KeyOptions::EcdsaP256Sha256,
            key_type: KeyOptions::EcdsaP256Sha256,
            role: CertificateRole::AdacCrtRoleLeaf,
            usage: CertificateUsage::AdacUsageNeutral,
            policies: 0,
            lifecycle: 0,
            oem_constraint: 0,
            extensions_bytes: 0,
            soc_class: 0,
            soc_id: [0x00u8; 16],
            permissions_mask: [0xFFu8; 16],
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct TokenHeader {
    pub format_version: AdacVersion,
    pub signature_type: KeyOptions,
    // Must be set to zero.
    pub _reserved: u8,
    pub extensions_bytes: u32,
    pub requested_permissions: [u8; 16],
}

impl Default for TokenHeader {
    fn default() -> Self {
        Self {
            format_version: AdacVersion { major: 1, minor: 0 },
            signature_type: KeyOptions::EcdsaP256Sha256,
            _reserved: 0,
            extensions_bytes: 0,
            requested_permissions: [0xFFu8; 16],
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct AdacTlvHeader {
    pub _reserved: u16,
    pub type_id: u16,
    pub length: u32,
}

impl AdacTlvHeader {
    fn new(type_id: u16, length: u32) -> Self {
        Self {
            _reserved: 0,
            type_id,
            length,
        }
    }

    fn to_le_bytes(self) -> [u8; size_of::<Self>()] {
        let mut bytes = [0u8; size_of::<Self>()];
        bytes[..2].copy_from_slice(&self._reserved.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.type_id.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.length.to_le_bytes());
        bytes
    }
}

pub fn tlv_wrap(type_id: u16, content: Vec<u8>) -> Vec<u8> {
    let header = AdacTlvHeader::new(type_id, content.len() as u32);
    let pad = if content.len().is_multiple_of(4) {
        0
    } else {
        4 - (content.len() % 4)
    };
    let mut tlv = Vec::<u8>::with_capacity(size_of::<AdacTlvHeader>() + content.len() + pad);
    tlv.extend_from_slice(&header.to_le_bytes());
    tlv.extend_from_slice(content.as_slice());
    if pad != 0 {
        tlv.extend_from_slice(&vec![0u8; pad]);
    }

    tlv
}

pub fn validate_signature_padding(
    key_type: KeyOptions,
    signature: &[u8],
) -> Result<&[u8], AdacError> {
    let (unpadded, padding) = match key_type {
        KeyOptions::Ed448Shake256 => signature
            .split_at_checked(ED448_SIGNATURE_SIZE_UNPADDED)
            .ok_or(AdacError::InvalidLength)?,
        KeyOptions::MlDsa65Sha384 => signature
            .split_at_checked(MLDSA_65_SIGNATURE_UNPADDED)
            .ok_or(AdacError::InvalidLength)?,
        KeyOptions::MlDsa87Sha512 => signature
            .split_at_checked(MLDSA_87_SIGNATURE_UNPADDED)
            .ok_or(AdacError::InvalidLength)?,
        _ => return Ok(signature),
    };

    if padding.iter().any(|b| *b != 0) {
        return Err(AdacError::Encoding("Invalid signature padding".to_string()));
    }

    Ok(unpadded)
}

pub fn validate_public_key_padding(
    key_type: KeyOptions,
    public_key: &[u8],
) -> Result<&[u8], AdacError> {
    if key_type != KeyOptions::Ed448Shake256 {
        return Ok(public_key);
    }

    if public_key.len() != ED448_PUBLIC_KEY_SIZE {
        return Err(AdacError::InvalidLength);
    }

    let (unpadded, padding) = public_key
        .split_at_checked(ED448_PUBLIC_KEY_SIZE_UNPADDED)
        .ok_or(AdacError::InvalidLength)?;
    if padding.iter().any(|b| *b != 0) {
        return Err(AdacError::Encoding(
            "Invalid public key padding".to_string(),
        ));
    }

    Ok(unpadded)
}

pub const ECDSA_P256_PUBLIC_KEY_SIZE: usize = 64;
pub const ECDSA_P256_SIGNATURE_SIZE: usize = 64;
pub const ECDSA_P256_HASH_SIZE: usize = 32;

pub const ECDSA_P384_PUBLIC_KEY_SIZE: usize = 96;
pub const ECDSA_P384_SIGNATURE_SIZE: usize = 96;
pub const ECDSA_P384_HASH_SIZE: usize = 48;

pub const ECDSA_P521_PUBLIC_KEY_SIZE: usize = 132;
pub const ECDSA_P521_SIGNATURE_SIZE: usize = 132;
pub const ECDSA_P521_HASH_SIZE: usize = 64;

pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;
pub const ED25519_HASH_SIZE: usize = 64;

pub const ED448_PUBLIC_KEY_SIZE: usize = 60;
pub const ED448_PUBLIC_KEY_SIZE_UNPADDED: usize = 57;
pub const ED448_SIGNATURE_SIZE: usize = 116;
pub const ED448_SIGNATURE_SIZE_UNPADDED: usize = 114;
pub const ED448_HASH_SIZE: usize = 64;

pub const MLDSA_44_PUBLIC_KEY_SIZE: usize = 1312;
pub const MLDSA_44_SIGNATURE_SIZE: usize = 2420;
pub const MLDSA_44_HASH_SIZE: usize = 32;

pub const MLDSA_65_PUBLIC_KEY_SIZE: usize = 1952;
pub const MLDSA_65_SIGNATURE_SIZE: usize = 3312; // 3 bytes padding
pub const MLDSA_65_SIGNATURE_UNPADDED: usize = 3309;
pub const MLDSA_65_HASH_SIZE: usize = 48;

pub const MLDSA_87_PUBLIC_KEY_SIZE: usize = 2592;
pub const MLDSA_87_SIGNATURE_SIZE: usize = 4628; // 1 byte padding
pub const MLDSA_87_SIGNATURE_UNPADDED: usize = 4627;
pub const MLDSA_87_HASH_SIZE: usize = 64;

pub const RSA_3072_PUBLIC_KEY_SIZE: usize = 384;
pub const RSA_3072_SIGNATURE_SIZE: usize = 384;
pub const RSA_3072_HASH_SIZE: usize = 32;

pub const RSA_4096_PUBLIC_KEY_SIZE: usize = 512;
pub const RSA_4096_SIGNATURE_SIZE: usize = 512;
pub const RSA_4096_HASH_SIZE: usize = 32;

pub const SM2_PUBLIC_KEY_SIZE: usize = 64;
pub const SM2_SIGNATURE_SIZE: usize = 64;
pub const SM2_HASH_SIZE: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_signature_padding_returns_unpadded_ed448_signature() {
        let mut signature = vec![0xAA; ED448_SIGNATURE_SIZE_UNPADDED];
        signature.extend_from_slice(&[0u8; ED448_SIGNATURE_SIZE - ED448_SIGNATURE_SIZE_UNPADDED]);

        let validated = validate_signature_padding(KeyOptions::Ed448Shake256, &signature).unwrap();

        assert_eq!(validated, &signature[..ED448_SIGNATURE_SIZE_UNPADDED]);
    }

    #[test]
    fn validate_signature_padding_rejects_nonzero_ed448_padding() {
        let mut signature = vec![0xAA; ED448_SIGNATURE_SIZE];
        signature[ED448_SIGNATURE_SIZE_UNPADDED] = 1;

        assert!(matches!(
            validate_signature_padding(KeyOptions::Ed448Shake256, &signature),
            Err(AdacError::Encoding(message)) if message == "Invalid signature padding"
        ));
    }

    #[test]
    fn validate_signature_padding_rejects_nonzero_mldsa65_padding() {
        let mut signature = vec![0xAA; MLDSA_65_SIGNATURE_SIZE];
        signature[MLDSA_65_SIGNATURE_UNPADDED] = 1;

        assert!(matches!(
            validate_signature_padding(KeyOptions::MlDsa65Sha384, &signature),
            Err(AdacError::Encoding(message)) if message == "Invalid signature padding"
        ));
    }

    #[test]
    fn validate_signature_padding_rejects_invalid_padded_signature_length() {
        let signature = vec![0xAA; ED448_SIGNATURE_SIZE_UNPADDED - 1];

        assert!(matches!(
            validate_signature_padding(KeyOptions::Ed448Shake256, &signature),
            Err(AdacError::InvalidLength)
        ));
    }

    #[test]
    fn validate_public_key_padding_returns_unpadded_ed448_public_key() {
        let mut public_key = vec![0xAA; ED448_PUBLIC_KEY_SIZE_UNPADDED];
        public_key
            .extend_from_slice(&[0u8; ED448_PUBLIC_KEY_SIZE - ED448_PUBLIC_KEY_SIZE_UNPADDED]);

        let validated =
            validate_public_key_padding(KeyOptions::Ed448Shake256, &public_key).unwrap();

        assert_eq!(validated, &public_key[..ED448_PUBLIC_KEY_SIZE_UNPADDED]);
    }

    #[test]
    fn validate_public_key_padding_rejects_nonzero_ed448_padding() {
        let mut public_key = vec![0xAA; ED448_PUBLIC_KEY_SIZE];
        public_key[ED448_PUBLIC_KEY_SIZE_UNPADDED] = 1;

        assert!(matches!(
            validate_public_key_padding(KeyOptions::Ed448Shake256, &public_key),
            Err(AdacError::Encoding(message)) if message == "Invalid public key padding"
        ));
    }

    #[test]
    fn validate_public_key_padding_rejects_unpadded_ed448_public_key() {
        let public_key = vec![0xAA; ED448_PUBLIC_KEY_SIZE_UNPADDED];

        assert!(matches!(
            validate_public_key_padding(KeyOptions::Ed448Shake256, &public_key),
            Err(AdacError::InvalidLength)
        ));
    }
}
