// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::traits::*;
use adac::{AdacError, KeyOptions};
use adac_cryptoki::{private, public};
use cryptoki::{object::ObjectHandle, session::Session};
use zeroize::Zeroizing;

pub struct Pkcs11Provider {
    session: Session,
    current_key: Option<ObjectHandle>,
}

impl Pkcs11Provider {
    pub fn new<P>(module: String, pin: P, token_label: Option<String>) -> Result<Self, AdacError>
    where
        P: Into<Zeroizing<String>>,
    {
        let (_pkcs11, _slot, session) =
            adac_cryptoki::pkcs11_create_session(module, pin, token_label)?;

        Ok(Self {
            session,
            current_key: None,
        })
    }

    pub fn import_key(
        &mut self,
        key_type: KeyOptions,
        key: Vec<u8>,
    ) -> Result<(String, Vec<u8>, Vec<u8>, ObjectHandle, ObjectHandle), AdacError> {
        private::import_key(&self.session, key_type, key)
    }

    pub fn generate_key(
        &mut self,
        key_type: KeyOptions,
    ) -> Result<(String, Vec<u8>, Vec<u8>, ObjectHandle, ObjectHandle), AdacError> {
        private::generate_keypair(&self.session, key_type)
    }
}

impl AdacCryptoProvider for Pkcs11Provider {
    fn verify(
        &self,
        key_type: KeyOptions,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), AdacError> {
        let handle = public::import_public_key(&self.session, key_type, public_key)?;
        public::verify(&self.session, key_type, handle, data, signature)
    }

    fn hash(&self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, AdacError> {
        adac_cryptoki::hash(&self.session, key_type, data)
    }

    fn sign(&mut self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, AdacError> {
        let key = self
            .current_key
            .ok_or(AdacError::CryptoProviderError("No key loaded".to_string()))?;

        private::sign(&self.session, key_type, key, data)
    }

    fn load_key(
        &mut self,
        key_type: KeyOptions,
        format: AdacKeyFormat,
        key: &[u8],
    ) -> Result<Vec<u8>, AdacError> {
        if format == AdacKeyFormat::KeyId {
            let (private, public) = private::find_keypair(&self.session, key_type, key)?;
            let public_key = public::load_public_key(&self.session, key_type, public)?;
            self.current_key = Some(private);
            Ok(public_key)
        } else {
            Err(AdacError::CryptoProviderError(
                "Unsupported key format".to_string(),
            ))
        }
    }
}
