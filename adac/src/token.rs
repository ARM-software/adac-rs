// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::traits::AdacCryptoProvider;
use crate::{AdacError, KeyOptions, TokenHeader};
use std::mem::{MaybeUninit, offset_of};

pub struct AdacToken {
    token: Vec<u8>,
    key_type: KeyOptions,
    hash_size: usize,
    sig_size: usize,
    header: TokenHeader,
}

pub fn adac_sizes_from_crypto(key_type: KeyOptions) -> Result<(usize, usize), AdacError> {
    let (_, hash_size, sig_size) = match key_type {
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
        _ => return Err(AdacError::UnsupportedAlgorithm),
    };
    Ok((hash_size, sig_size))
}

impl AdacToken {
    const HEADER_SIZE: usize = core::mem::size_of::<TokenHeader>();

    pub fn from_bytes(token: Vec<u8>) -> Result<Self, AdacError> {
        if token.len() < Self::HEADER_SIZE {
            return Err(AdacError::InvalidLength);
        }

        let header = &token[..Self::HEADER_SIZE];
        let key_type = match KeyOptions::try_from(header[offset_of!(TokenHeader, signature_type)]) {
            Ok(k) => k,
            Err(()) => return Err(AdacError::InconsistentCrypto),
        };
        let header = unsafe {
            let mut h = MaybeUninit::<TokenHeader>::uninit();
            core::ptr::copy_nonoverlapping(
                token.as_ptr(),
                h.as_mut_ptr() as *mut u8,
                Self::HEADER_SIZE,
            );
            h.assume_init()
        };
        if key_type != header.signature_type {
            return Err(AdacError::InconsistentCrypto);
        }

        let (hash_size, sig_size) = crate::token::adac_sizes_from_crypto(key_type)?;

        if Self::HEADER_SIZE + hash_size + sig_size + (header.extensions_bytes as usize)
            != token.len()
        {
            return Err(AdacError::InvalidLength);
        }

        Ok(Self {
            token,
            key_type,
            hash_size,
            sig_size,
            header,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.token.clone()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.token.as_slice()
    }

    pub fn header(&self) -> &TokenHeader {
        &self.header
    }

    pub fn get_extensions_hash(&self) -> &[u8] {
        let l = Self::HEADER_SIZE;
        &self.token[l..(l + self.hash_size)]
    }

    pub fn get_signature(&self) -> &[u8] {
        let l = Self::HEADER_SIZE + self.hash_size;
        &self.token[l..(l + self.sig_size)]
    }

    pub fn get_tbs(&self) -> &[u8] {
        let l = Self::HEADER_SIZE + self.hash_size;
        &self.token[0..l]
    }

    pub fn get_extensions(&self) -> &[u8] {
        let l = Self::HEADER_SIZE + self.hash_size + self.sig_size;
        &self.token[l..(l + self.header.extensions_bytes as usize)]
    }

    pub fn sign(
        key_type: KeyOptions,
        header: TokenHeader,
        extensions: Option<&[u8]>,
        challenge: &[u8],
        provider: &mut dyn AdacCryptoProvider,
    ) -> Result<Self, AdacError> {
        let mut h = header;
        let (_pubkey_size, hash_size, sig_size) =
            crate::certificate::adac_sizes_from_crypto(key_type)?;

        if key_type != h.signature_type {
            return Err(AdacError::InconsistentCrypto);
        }
        crate::validate_token_challenge(challenge)?;

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

        let mut token = Vec::<u8>::with_capacity(
            size_of::<TokenHeader>() + hash_size + sig_size + h.extensions_bytes as usize,
        );

        token.extend_from_slice(unsafe {
            ::core::slice::from_raw_parts(
                &h as *const TokenHeader as *const u8,
                size_of::<TokenHeader>(),
            )
        });
        token.extend_from_slice(extension_hash.as_slice());

        let mut tbs =
            Vec::<u8>::with_capacity(size_of::<TokenHeader>() + hash_size + challenge.len());
        tbs.extend_from_slice(token.as_slice());
        tbs.extend_from_slice(challenge);

        let signature = provider.sign(key_type, tbs.as_slice())?;
        token.extend_from_slice(signature.as_slice());
        if let Some(e) = extensions {
            token.extend_from_slice(e);
        }

        Self::from_bytes(token)
    }

    pub fn verify(
        &self,
        public_key: &[u8],
        challenge: &[u8],
        provider: &dyn AdacCryptoProvider,
    ) -> Result<(), AdacError> {
        crate::validate_token_challenge(challenge)?;

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

        let mut tbs =
            Vec::<u8>::with_capacity(Self::HEADER_SIZE + self.hash_size + challenge.len());
        tbs.extend_from_slice(self.get_tbs());
        tbs.extend_from_slice(challenge);

        provider.verify(
            self.key_type,
            public_key,
            tbs.as_slice(),
            self.get_signature(),
        )
    }
}
