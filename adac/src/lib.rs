// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod certificate;
pub mod token;
pub mod traits;

#[derive(Debug, Clone)]
pub enum AdacError {
    InvalidLength,
    InvalidPadding,
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

/// ADAC certificate header serialized layout.
///
/// Multi-byte integer fields are encoded little-endian by the explicit
/// serialization helpers.
///
/// ```text
/// +--------+------+------------------+-------------------------------+
/// | Offset | Size | Field            | Encoding                      |
/// +--------+------+------------------+-------------------------------+
/// |      0 |    2 | format_version   | major: u8, minor: u8          |
/// |      2 |    1 | signature_type   | KeyOptions discriminant       |
/// |      3 |    1 | key_type         | KeyOptions discriminant       |
/// |      4 |    1 | role             | CertificateRole discriminant  |
/// |      5 |    1 | usage            | CertificateUsage discriminant |
/// |      6 |    2 | policies         | u16 little-endian             |
/// |      8 |    2 | lifecycle        | u16 little-endian             |
/// |     10 |    2 | oem_constraint   | u16 little-endian             |
/// |     12 |    4 | extensions_bytes | u32 little-endian             |
/// |     16 |    4 | soc_class        | u32 little-endian             |
/// |     20 |   16 | soc_id           | 128-bit value                 |
/// |     36 |   16 | permissions_mask | 128-bit value                 |
/// +--------+------+------------------+-------------------------------+
/// | Total  |   52 |                  |                               |
/// +--------+------+------------------+-------------------------------+
/// ```
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

impl CertificateHeader {
    pub const SIZE: usize = 52;

    pub fn validate(&self) -> Result<(), AdacError> {
        let version = self.format_version;
        if version.major != 1 || version.minor > 1 {
            return Err(AdacError::InconsistentVersion);
        }

        if self.key_type != self.signature_type {
            return Err(AdacError::InconsistentCrypto);
        }

        if self.format_version == (AdacVersion { major: 1, minor: 0 }) {
            match self.key_type {
                KeyOptions::EcdsaP384Sha384
                | KeyOptions::MlDsa44Sha256
                | KeyOptions::MlDsa65Sha384
                | KeyOptions::MlDsa87Sha512 => return Err(AdacError::InconsistentVersion),
                _ => {}
            }

            if self.policies != 0x0 {
                return Err(AdacError::InconsistentVersion);
            }
        }

        Ok(())
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, AdacError> {
        if bytes.len() != Self::SIZE {
            return Err(AdacError::InvalidLength);
        }

        let mut soc_id = [0u8; 16];
        soc_id.copy_from_slice(&bytes[20..36]);
        let mut permissions_mask = [0u8; 16];
        permissions_mask.copy_from_slice(&bytes[36..52]);

        let header = Self {
            format_version: AdacVersion {
                major: bytes[0],
                minor: bytes[1],
            },
            signature_type: KeyOptions::try_from(bytes[2])
                .map_err(|_| AdacError::InconsistentCrypto)?,
            key_type: KeyOptions::try_from(bytes[3]).map_err(|_| AdacError::InconsistentCrypto)?,
            role: CertificateRole::try_from(bytes[4]).map_err(|_| {
                AdacError::Encoding("Invalid value for certificate role".to_string())
            })?,
            usage: CertificateUsage::try_from(bytes[5]).map_err(|_| {
                AdacError::Encoding("Invalid value for certificate usage".to_string())
            })?,
            policies: u16::from_le_bytes([bytes[6], bytes[7]]),
            lifecycle: u16::from_le_bytes([bytes[8], bytes[9]]),
            oem_constraint: u16::from_le_bytes([bytes[10], bytes[11]]),
            extensions_bytes: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            soc_class: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            soc_id,
            permissions_mask,
        };
        header.validate()?;
        Ok(header)
    }

    pub(crate) fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.format_version.major;
        bytes[1] = self.format_version.minor;
        bytes[2] = self.signature_type as u8;
        bytes[3] = self.key_type as u8;
        bytes[4] = self.role as u8;
        bytes[5] = self.usage as u8;
        bytes[6..8].copy_from_slice(&self.policies.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.lifecycle.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.oem_constraint.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.extensions_bytes.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.soc_class.to_le_bytes());
        bytes[20..36].copy_from_slice(&self.soc_id);
        bytes[36..52].copy_from_slice(&self.permissions_mask);
        bytes
    }
}

/// ADAC token header serialized layout.
///
/// Multi-byte integer fields are encoded little-endian by the explicit
/// serialization helpers.
///
/// ```text
/// +--------+------+-----------------------+--------------------------+
/// | Offset | Size | Field                 | Encoding                 |
/// +--------+------+-----------------------+--------------------------+
/// |      0 |    2 | format_version        | major: u8, minor: u8     |
/// |      2 |    1 | signature_type        | KeyOptions discriminant  |
/// |      3 |    1 | _reserved             | must be zero             |
/// |      4 |    4 | extensions_bytes      | u32 little-endian        |
/// |      8 |   16 | requested_permissions | 128-bit value            |
/// +--------+------+-----------------------+--------------------------+
/// | Total  |   24 |                       |                          |
/// +--------+------+-----------------------+--------------------------+
/// ```
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

impl TokenHeader {
    pub const SIZE: usize = 24;

    pub fn validate(&self) -> Result<(), AdacError> {
        if self.format_version.major != 1 || self.format_version.minor > 1 {
            return Err(AdacError::InconsistentVersion);
        }
        if self._reserved != 0 {
            return Err(AdacError::Encoding(
                "Invalid nonzero token reserved field".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, AdacError> {
        if bytes.len() != Self::SIZE {
            return Err(AdacError::InvalidLength);
        }

        let mut requested_permissions = [0u8; 16];
        requested_permissions.copy_from_slice(&bytes[8..24]);

        let header = Self {
            format_version: AdacVersion {
                major: bytes[0],
                minor: bytes[1],
            },
            signature_type: KeyOptions::try_from(bytes[2])
                .map_err(|_| AdacError::InconsistentCrypto)?,
            _reserved: bytes[3],
            extensions_bytes: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            requested_permissions,
        };
        header.validate()?;
        Ok(header)
    }

    pub(crate) fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.format_version.major;
        bytes[1] = self.format_version.minor;
        bytes[2] = self.signature_type as u8;
        bytes[3] = self._reserved;
        bytes[4..8].copy_from_slice(&self.extensions_bytes.to_le_bytes());
        bytes[8..24].copy_from_slice(&self.requested_permissions);
        bytes
    }
}

/// ADAC TLV container header serialized layout.
///
/// Multi-byte integer fields are encoded little-endian.
///
/// ```text
/// +--------+------+-----------+-------------------+--------------------------------+
/// | Offset | Size | Field     | Encoding          | Meaning                        |
/// +--------+------+-----------+-------------------+--------------------------------+
/// |      0 |    1 | flags     | u8                | TLV flags                      |
/// |      1 |    1 | _reserved | u8                | must be zero                   |
/// |      2 |    2 | type_id   | u16 little-endian | TLV type identifier            |
/// |      4 |    4 | length    | u32 little-endian | value length, excludes padding |
/// +--------+------+-----------+-------------------+--------------------------------+
/// | Total  |    8 |           |                   |                                |
/// +--------+------+-----------+-------------------+--------------------------------+
/// ```
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct AdacTlvHeader {
    pub flags: u8,
    pub _reserved: u8,
    pub type_id: u16,
    pub length: u32,
}

pub const TLV_FLAG_CRITICAL: u8 = 0x01;

#[derive(Debug, Copy, Clone)]
pub struct AdacTlv<'a> {
    pub header: AdacTlvHeader,
    pub value: &'a [u8],
}

impl AdacTlvHeader {
    pub const SIZE: usize = 8;

    fn new_with_flags(type_id: u16, flags: u8, length: u32) -> Self {
        Self {
            flags,
            _reserved: 0,
            type_id,
            length,
        }
    }

    fn padded_value_len(&self) -> Result<usize, AdacError> {
        let length = self.length as usize;
        length
            .checked_add(tlv_padding_len(length))
            .ok_or(AdacError::InvalidLength)
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0] = self.flags;
        bytes[1] = self._reserved;
        bytes[2..4].copy_from_slice(&self.type_id.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.length.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdacError> {
        if bytes.len() != Self::SIZE {
            return Err(AdacError::InvalidLength);
        }

        let header = Self {
            flags: bytes[0],
            _reserved: bytes[1],
            type_id: u16::from_le_bytes([bytes[2], bytes[3]]),
            length: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        };
        if header._reserved != 0 {
            return Err(AdacError::Encoding(
                "Invalid nonzero TLV reserved field".to_string(),
            ));
        }
        Ok(header)
    }
}

pub fn decode_tlv_header(bytes: &[u8]) -> Result<AdacTlvHeader, AdacError> {
    AdacTlvHeader::from_bytes(bytes)
}

fn tlv_padding_len(length: usize) -> usize {
    (4 - (length % 4)) % 4
}

pub fn parse_tlv_sequence(mut bytes: &[u8]) -> Result<Vec<AdacTlv<'_>>, AdacError> {
    let mut tlvs = Vec::<AdacTlv>::new();

    while !bytes.is_empty() {
        if bytes.len() < AdacTlvHeader::SIZE {
            return Err(AdacError::InvalidLength);
        }

        let header = AdacTlvHeader::from_bytes(&bytes[..AdacTlvHeader::SIZE])?;
        let value_len = header.length as usize;
        let padded_value_len = header.padded_value_len()?;
        let total_len = AdacTlvHeader::SIZE
            .checked_add(padded_value_len)
            .ok_or(AdacError::InvalidLength)?;

        if total_len > bytes.len() {
            return Err(AdacError::InvalidLength);
        }

        let value_start = AdacTlvHeader::SIZE;
        let value_end = value_start + value_len;
        let padding_end = value_start + padded_value_len;
        if bytes[value_end..padding_end].iter().any(|b| *b != 0) {
            return Err(AdacError::InvalidPadding);
        }

        tlvs.push(AdacTlv {
            header,
            value: &bytes[value_start..value_end],
        });
        bytes = &bytes[total_len..];
    }

    Ok(tlvs)
}

pub fn validate_format_version(version: AdacVersion) -> Result<(), AdacError> {
    if version.major != 1 || version.minor > 1 {
        return Err(AdacError::InconsistentVersion);
    }
    Ok(())
}

pub fn validate_certificate_version(version: AdacVersion, policies: u16) -> Result<(), AdacError> {
    validate_format_version(version)?;
    if version == (AdacVersion { major: 1, minor: 0 }) && policies != 0 {
        return Err(AdacError::InconsistentVersion);
    }
    Ok(())
}

pub fn tlv_wrap(type_id: u16, content: Vec<u8>) -> Vec<u8> {
    tlv_wrap_with_flags(type_id, 0, &content)
}

pub fn tlv_wrap_with_flags(type_id: u16, flags: u8, content: &[u8]) -> Vec<u8> {
    let header = AdacTlvHeader::new_with_flags(type_id, flags, content.len() as u32);
    let pad = tlv_padding_len(content.len());
    let mut tlv = Vec::<u8>::with_capacity(AdacTlvHeader::SIZE + content.len() + pad);
    tlv.extend_from_slice(&header.to_bytes());
    tlv.extend_from_slice(content);
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

pub const TOKEN_CHALLENGE_SIZE: usize = 32;

pub fn validate_token_challenge(challenge: &[u8]) -> Result<(), AdacError> {
    if challenge.len() != TOKEN_CHALLENGE_SIZE {
        return Err(AdacError::InvalidLength);
    }

    Ok(())
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

    #[test]
    fn certificate_header_rejects_policies_for_version_1_0() {
        let header = CertificateHeader {
            policies: 1,
            ..Default::default()
        };

        assert!(matches!(
            header.validate(),
            Err(AdacError::InconsistentVersion)
        ));
    }

    #[test]
    fn token_header_rejects_nonzero_reserved_field() {
        let header = TokenHeader {
            _reserved: 1,
            ..Default::default()
        };

        assert!(matches!(
            header.validate(),
            Err(AdacError::Encoding(message))
                if message == "Invalid nonzero token reserved field"
        ));
    }

    #[test]
    fn certificate_from_bytes_rejects_unsupported_version() {
        let mut certificate = vec![0u8; CertificateHeader::SIZE];
        certificate[0] = 1;
        certificate[1] = 2;
        certificate[2] = KeyOptions::EcdsaP256Sha256 as u8;
        certificate[3] = KeyOptions::EcdsaP256Sha256 as u8;
        certificate[4] = CertificateRole::AdacCrtRoleLeaf as u8;
        certificate[5] = CertificateUsage::AdacUsageNeutral as u8;

        assert!(matches!(
            crate::certificate::AdacCertificate::from_bytes(certificate),
            Err(AdacError::InconsistentVersion)
        ));
    }

    #[test]
    fn certificate_from_bytes_rejects_policies_for_version_1_0() {
        let mut certificate = vec![0u8; CertificateHeader::SIZE];
        certificate[0] = 1;
        certificate[1] = 0;
        certificate[2] = KeyOptions::EcdsaP256Sha256 as u8;
        certificate[3] = KeyOptions::EcdsaP256Sha256 as u8;
        certificate[4] = CertificateRole::AdacCrtRoleLeaf as u8;
        certificate[5] = CertificateUsage::AdacUsageNeutral as u8;
        certificate[6..8].copy_from_slice(&1u16.to_le_bytes());

        assert!(matches!(
            crate::certificate::AdacCertificate::from_bytes(certificate),
            Err(AdacError::InconsistentVersion)
        ));
    }

    #[test]
    fn token_from_bytes_rejects_nonzero_reserved_field() {
        let mut token = vec![0u8; TokenHeader::SIZE];
        token[0] = 1;
        token[1] = 0;
        token[2] = KeyOptions::EcdsaP256Sha256 as u8;
        token[3] = 1;

        assert!(matches!(
            crate::token::AdacToken::from_bytes(token),
            Err(AdacError::Encoding(message))
                if message == "Invalid nonzero token reserved field"
        ));
    }

    #[test]
    fn token_from_bytes_rejects_unsupported_version() {
        let mut token = vec![0u8; TokenHeader::SIZE];
        token[0] = 1;
        token[1] = 2;
        token[2] = KeyOptions::EcdsaP256Sha256 as u8;

        assert!(matches!(
            crate::token::AdacToken::from_bytes(token),
            Err(AdacError::InconsistentVersion)
        ));
    }

    #[test]
    fn certificate_header_serialization_is_little_endian() {
        let soc_id = *b"0123456789ABCDEF";
        let permissions_mask = *b"fedcba9876543210";
        let header = CertificateHeader {
            format_version: AdacVersion { major: 1, minor: 1 },
            signature_type: KeyOptions::EcdsaP384Sha384,
            key_type: KeyOptions::EcdsaP384Sha384,
            role: CertificateRole::AdacCrtRoleRoot,
            usage: CertificateUsage::AdacUsageRma,
            policies: 0x1234,
            lifecycle: 0x4567,
            oem_constraint: 0x89ab,
            extensions_bytes: 0x01020304,
            soc_class: 0x05060708,
            soc_id,
            permissions_mask,
        };

        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), CertificateHeader::SIZE);
        assert_eq!(&bytes[0..8], &[1, 1, 0x0a, 0x0a, 1, 2, 0x34, 0x12]);
        assert_eq!(&bytes[8..12], &[0x67, 0x45, 0xab, 0x89]);
        assert_eq!(&bytes[12..16], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&bytes[16..20], &[0x08, 0x07, 0x06, 0x05]);
        assert_eq!(&bytes[20..36], &soc_id);
        assert_eq!(&bytes[36..52], &permissions_mask);

        let decoded = CertificateHeader::from_bytes(&bytes).unwrap();
        let policies = decoded.policies;
        let lifecycle = decoded.lifecycle;
        let oem_constraint = decoded.oem_constraint;
        let extensions_bytes = decoded.extensions_bytes;
        let soc_class = decoded.soc_class;
        let decoded_soc_id = decoded.soc_id;
        let decoded_permissions_mask = decoded.permissions_mask;
        assert_eq!(decoded.format_version, AdacVersion { major: 1, minor: 1 });
        assert_eq!(decoded.signature_type, KeyOptions::EcdsaP384Sha384);
        assert_eq!(decoded.key_type, KeyOptions::EcdsaP384Sha384);
        assert_eq!(decoded.role, CertificateRole::AdacCrtRoleRoot);
        assert_eq!(decoded.usage, CertificateUsage::AdacUsageRma);
        assert_eq!(policies, 0x1234);
        assert_eq!(lifecycle, 0x4567);
        assert_eq!(oem_constraint, 0x89ab);
        assert_eq!(extensions_bytes, 0x01020304);
        assert_eq!(soc_class, 0x05060708);
        assert_eq!(decoded_soc_id, soc_id);
        assert_eq!(decoded_permissions_mask, permissions_mask);
    }

    #[test]
    fn token_header_serialization_is_little_endian() {
        let requested_permissions = *b"0123456789ABCDEF";
        let header = TokenHeader {
            format_version: AdacVersion { major: 1, minor: 1 },
            signature_type: KeyOptions::MlDsa87Sha512,
            _reserved: 0,
            extensions_bytes: 0x01020304,
            requested_permissions,
        };

        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), TokenHeader::SIZE);
        assert_eq!(&bytes[0..8], &[1, 1, 0x0d, 0, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&bytes[8..24], &requested_permissions);

        let decoded = TokenHeader::from_bytes(&bytes).unwrap();
        let extensions_bytes = decoded.extensions_bytes;
        let decoded_requested_permissions = decoded.requested_permissions;
        assert_eq!(decoded.format_version, AdacVersion { major: 1, minor: 1 });
        assert_eq!(decoded.signature_type, KeyOptions::MlDsa87Sha512);
        assert_eq!(decoded._reserved, 0);
        assert_eq!(extensions_bytes, 0x01020304);
        assert_eq!(decoded_requested_permissions, requested_permissions);
    }

    #[test]
    fn tlv_header_serialization_rejects_nonzero_reserved_field() {
        let bytes = [0, 1, 1, 2, 4, 0, 0, 0];

        assert!(matches!(
            AdacTlvHeader::from_bytes(&bytes),
            Err(AdacError::Encoding(message))
                if message == "Invalid nonzero TLV reserved field"
        ));
    }

    #[test]
    fn tlv_header_serialization_accepts_critical_flag() {
        let bytes = [TLV_FLAG_CRITICAL, 0, 1, 2, 4, 0, 0, 0];
        let header = AdacTlvHeader::from_bytes(&bytes).unwrap();
        let flags = header.flags;
        let reserved = header._reserved;
        let type_id = header.type_id;
        let length = header.length;

        assert_eq!(flags, TLV_FLAG_CRITICAL);
        assert_eq!(reserved, 0);
        assert_eq!(type_id, 0x0201);
        assert_eq!(length, 4);
    }

    #[test]
    fn tlv_sequence_parser_advances_over_zero_padding() {
        let mut bytes = tlv_wrap_with_flags(0x1234, TLV_FLAG_CRITICAL, b"abc");
        bytes.extend_from_slice(&tlv_wrap(0x1235, vec![1, 2, 3, 4]));

        let tlvs = parse_tlv_sequence(&bytes).unwrap();
        let first_flags = tlvs[0].header.flags;
        let first_type_id = tlvs[0].header.type_id;
        let first_length = tlvs[0].header.length;
        let second_type_id = tlvs[1].header.type_id;

        assert_eq!(tlvs.len(), 2);
        assert_eq!(first_flags, TLV_FLAG_CRITICAL);
        assert_eq!(first_type_id, 0x1234);
        assert_eq!(first_length, 3);
        assert_eq!(tlvs[0].value, b"abc");
        assert_eq!(second_type_id, 0x1235);
        assert_eq!(tlvs[1].value, &[1, 2, 3, 4]);
    }

    #[test]
    fn tlv_sequence_parser_rejects_nonzero_padding() {
        let mut bytes = tlv_wrap(0x1234, vec![1]);
        let last = bytes.len() - 1;
        bytes[last] = 1;

        assert!(matches!(
            parse_tlv_sequence(&bytes),
            Err(AdacError::InvalidPadding)
        ));
    }
}
