// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod ec_utils;
pub mod private;
pub mod public;

use adac::KeyOptions::*;
use adac::{AdacError, KeyOptions};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

pub fn pkcs11_create_session(
    module: String,
    pin: String,
    token_label: Option<String>,
) -> (Pkcs11, Slot, Session) {
    let pkcs11 = Pkcs11::new(module).unwrap();

    // initialize the library
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .unwrap();

    // find a slot, get the first one
    let slots = pkcs11.get_slots_with_token().unwrap();
    let slot = if let Some(label) = token_label {
        let mut slot = slots[0];
        for s in &slots {
            if let Ok(token_info) = pkcs11.get_token_info(*s)
                && token_info.label().eq(&label)
            {
                slot = *s;
            }
        }
        slot
    } else {
        slots[0]
    };

    // open a session
    let session = pkcs11.open_rw_session(slot).unwrap();

    // log in the session
    session
        .login(UserType::User, Some(&AuthPin::new(pin.into())))
        .unwrap();

    (pkcs11, slot, session)
}

pub fn hash(session: &Session, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, AdacError> {
    match key_type {
        EcdsaP256Sha256 | Rsa3072Sha256 | Rsa4096Sha256 => session
            .digest(&Mechanism::Sha256, data)
            .map_err(|e| AdacError::CryptoProviderError(e.to_string())),
        EcdsaP384Sha384 => session
            .digest(&Mechanism::Sha384, data)
            .map_err(|e| AdacError::CryptoProviderError(e.to_string())),
        EcdsaP521Sha512 | Ed25519Sha512 => session
            .digest(&Mechanism::Sha512, data)
            .map_err(|e| AdacError::CryptoProviderError(e.to_string())),
        Ed448Shake256 => Ok(adac_crypto_rust::ed_448::shake256_digest(data)),
        _ => Err(AdacError::UnsupportedAlgorithm),
    }
}
