// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::traits::AdacCryptoProvider;
use crate::{
    AdacError, AdacVersion, CertificateHeader, CertificateRole, CertificateUsage, KeyOptions,
};
use core::mem::{MaybeUninit, size_of};
use std::mem::offset_of;

pub struct AdacCertificate {
    certificate: Vec<u8>,
    key_type: KeyOptions,
    pubkey_size: usize,
    hash_size: usize,
    sig_size: usize,
    header: CertificateHeader,
}

pub fn adac_sizes_from_crypto(key_type: KeyOptions) -> Result<(usize, usize, usize), AdacError> {
    let (pubkey_size, hash_size, sig_size) = match key_type {
        KeyOptions::EcdsaP256Sha256 => (
            crate::ECDSA_P256_PUBLIC_KEY_SIZE,
            crate::ECDSA_P256_HASH_SIZE,
            crate::ECDSA_P256_SIGNATURE_SIZE,
        ),
        KeyOptions::EcdsaP384Sha384 => (
            crate::ECDSA_P384_PUBLIC_KEY_SIZE,
            crate::ECDSA_P384_HASH_SIZE,
            crate::ECDSA_P384_SIGNATURE_SIZE,
        ),
        KeyOptions::EcdsaP521Sha512 => (
            crate::ECDSA_P521_PUBLIC_KEY_SIZE,
            crate::ECDSA_P521_HASH_SIZE,
            crate::ECDSA_P521_SIGNATURE_SIZE,
        ),
        KeyOptions::Ed25519Sha512 => (
            crate::ED25519_PUBLIC_KEY_SIZE,
            crate::ED25519_HASH_SIZE,
            crate::ED25519_SIGNATURE_SIZE,
        ),
        KeyOptions::Ed448Shake256 => (
            crate::ED448_PUBLIC_KEY_SIZE,
            crate::ED448_HASH_SIZE,
            crate::ED448_SIGNATURE_SIZE,
        ),
        KeyOptions::MlDsa44Sha256 => (
            crate::MLDSA_44_PUBLIC_KEY_SIZE,
            crate::MLDSA_44_HASH_SIZE,
            crate::MLDSA_44_SIGNATURE_SIZE,
        ),
        KeyOptions::MlDsa65Sha384 => (
            crate::MLDSA_65_PUBLIC_KEY_SIZE,
            crate::MLDSA_65_HASH_SIZE,
            crate::MLDSA_65_SIGNATURE_SIZE,
        ),
        KeyOptions::MlDsa87Sha512 => (
            crate::MLDSA_87_PUBLIC_KEY_SIZE,
            crate::MLDSA_87_HASH_SIZE,
            crate::MLDSA_87_SIGNATURE_SIZE,
        ),
        KeyOptions::Rsa3072Sha256 => (
            crate::RSA_3072_PUBLIC_KEY_SIZE,
            crate::RSA_3072_HASH_SIZE,
            crate::RSA_3072_SIGNATURE_SIZE,
        ),
        KeyOptions::Rsa4096Sha256 => (
            crate::RSA_4096_PUBLIC_KEY_SIZE,
            crate::RSA_4096_HASH_SIZE,
            crate::RSA_4096_SIGNATURE_SIZE,
        ),
        KeyOptions::SmSm2Sm3 => (
            crate::SM2_PUBLIC_KEY_SIZE,
            crate::SM2_HASH_SIZE,
            crate::SM2_SIGNATURE_SIZE,
        ),
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };
    Ok((pubkey_size, hash_size, sig_size))
}

impl AdacCertificate {
    const HEADER_SIZE: usize = core::mem::size_of::<CertificateHeader>();

    pub fn from_bytes(certificate: Vec<u8>) -> Result<Self, AdacError> {
        if certificate.len() < Self::HEADER_SIZE {
            return Err(AdacError::InvalidLength);
        }

        let header = &certificate[..Self::HEADER_SIZE];
        if header[offset_of!(CertificateHeader, key_type)]
            != header[offset_of!(CertificateHeader, signature_type)]
        {
            return Err(AdacError::InconsistentCrypto);
        }
        let key_type = match KeyOptions::try_from(header[offset_of!(CertificateHeader, key_type)]) {
            Ok(k) => k,
            Err(()) => return Err(AdacError::InconsistentCrypto),
        };
        if CertificateRole::try_from(header[offset_of!(CertificateHeader, role)]).is_err() {
            return Err(AdacError::Encoding(
                "Invalid value for certificate role".to_string(),
            ));
        }
        if CertificateUsage::try_from(header[offset_of!(CertificateHeader, usage)]).is_err() {
            return Err(AdacError::Encoding(
                "Invalid value for certificate usage".to_string(),
            ));
        }
        let header = unsafe {
            let mut h = MaybeUninit::<CertificateHeader>::uninit();
            core::ptr::copy_nonoverlapping(
                certificate.as_ptr(),
                h.as_mut_ptr() as *mut u8,
                Self::HEADER_SIZE,
            );
            h.assume_init()
        };
        if key_type != header.key_type || key_type != header.signature_type {
            return Err(AdacError::InconsistentCrypto);
        }

        let (pubkey_size, hash_size, sig_size) = adac_sizes_from_crypto(key_type)?;

        let fixed = Self::HEADER_SIZE + pubkey_size + hash_size + sig_size;
        if match fixed.checked_add(header.extensions_bytes as usize) {
            None => true,                      // Fail if checked_add fails
            Some(l) => l != certificate.len(), // Fail if lengths do not match
        } {
            return Err(AdacError::InvalidLength);
        }

        crate::validate_public_key_padding(
            key_type,
            &certificate[Self::HEADER_SIZE..(Self::HEADER_SIZE + pubkey_size)],
        )?;

        Ok(Self {
            certificate,
            key_type,
            pubkey_size,
            hash_size,
            sig_size,
            header,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.certificate.clone()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.certificate.as_slice()
    }

    pub fn sign(
        key_type: KeyOptions,
        header: CertificateHeader,
        public_key: &[u8],
        extensions: Option<&[u8]>,
        provider: &mut dyn AdacCryptoProvider,
    ) -> Result<Self, AdacError> {
        let mut h = header;
        let (pubkey_size, hash_size, sig_size) = adac_sizes_from_crypto(key_type)?;

        if key_type != h.key_type || key_type != h.signature_type {
            return Err(AdacError::InconsistentCrypto);
        }

        if public_key.len() != pubkey_size {
            return Err(AdacError::InvalidLength);
        }
        crate::validate_public_key_padding(key_type, public_key)?;

        if header.format_version == (AdacVersion { major: 1, minor: 0 }) {
            match key_type {
                KeyOptions::EcdsaP384Sha384
                | KeyOptions::MlDsa44Sha256
                | KeyOptions::MlDsa65Sha384
                | KeyOptions::MlDsa87Sha512 => return Err(AdacError::InconsistentVersion),
                _ => {}
            }

            if header.policies != 0x0 {
                return Err(AdacError::InconsistentVersion);
            }
        }

        let extension_hash = match extensions {
            Some(extensions) => {
                h.extensions_bytes = extensions.len() as u32;
                provider.hash(key_type, extensions)?
            }
            None => {
                h.extensions_bytes = 0u32;
                vec![0u8; hash_size]
            }
        };

        if extension_hash.len() != hash_size {
            return Err(AdacError::InvalidLength);
        }

        let mut crt = Vec::<u8>::with_capacity(
            size_of::<CertificateHeader>()
                + pubkey_size
                + hash_size
                + sig_size
                + h.extensions_bytes as usize,
        );

        crt.extend_from_slice(unsafe {
            ::core::slice::from_raw_parts(
                &h as *const CertificateHeader as *const u8,
                size_of::<CertificateHeader>(),
            )
        });
        crt.extend_from_slice(public_key);
        crt.extend_from_slice(extension_hash.as_slice());

        let signature = provider.sign(key_type, crt.as_slice())?;
        crt.extend_from_slice(signature.as_slice());
        if let Some(e) = extensions {
            crt.extend_from_slice(e);
        }

        Self::from_bytes(crt)
    }

    pub fn header(&self) -> &CertificateHeader {
        &self.header
    }

    pub fn get_public_key(&self) -> &[u8] {
        let l = Self::HEADER_SIZE;
        &self.certificate[l..(l + self.pubkey_size)]
    }

    pub fn get_extensions_hash(&self) -> &[u8] {
        let l = Self::HEADER_SIZE + self.pubkey_size;
        &self.certificate[l..(l + self.hash_size)]
    }

    pub fn get_signature(&self) -> &[u8] {
        let l = Self::HEADER_SIZE + self.pubkey_size + self.hash_size;
        &self.certificate[l..(l + self.sig_size)]
    }

    pub fn get_tbs(&self) -> &[u8] {
        let l = Self::HEADER_SIZE + self.pubkey_size + self.hash_size;
        &self.certificate[0..l]
    }

    pub fn get_extensions(&self) -> &[u8] {
        let l = Self::HEADER_SIZE + self.pubkey_size + self.hash_size + self.sig_size;
        &self.certificate[l..(l + self.header.extensions_bytes as usize)]
    }

    pub fn verify(
        &self,
        public_key: &[u8],
        provider: &dyn AdacCryptoProvider,
    ) -> Result<(), AdacError> {
        if self.header().extensions_bytes == 0 {
            for h in self.get_extensions_hash() {
                if *h != 0x0 {
                    return Err(AdacError::Encoding("Invalid extensions hash".to_string()));
                }
            }
        } else {
            let hash = provider.hash(self.key_type, self.get_extensions())?;
            if hash != self.get_extensions_hash() {
                return Err(AdacError::Encoding("Invalid extensions hash".to_string()));
            }
        }

        provider.verify(
            self.key_type,
            public_key,
            self.get_tbs(),
            self.get_signature(),
        )
    }
}
