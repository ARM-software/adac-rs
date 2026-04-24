// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
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
) -> Result<(Pkcs11, Slot, Session), AdacError> {
    let pkcs11 = Pkcs11::new(module)
        .map_err(|e| AdacError::CryptoProviderError(format!("Loading PKCS#11 module: {e}")))?;

    // initialize the library
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|e| AdacError::CryptoProviderError(format!("Initializing PKCS#11 module: {e}")))?;

    // find a slot, get the first one
    let slots = pkcs11
        .get_slots_with_token()
        .map_err(|e| AdacError::CryptoProviderError(format!("Enumerating PKCS#11 slots: {e}")))?;
    if slots.is_empty() {
        return Err(AdacError::CryptoProviderError(
            "No PKCS#11 token slots with initialized tokens were found".to_string(),
        ));
    }
    let slot = if let Some(label) = token_label {
        slots
            .iter()
            .copied()
            .find(|slot| {
                pkcs11
                    .get_token_info(*slot)
                    .is_ok_and(|token_info| token_info.label() == label)
            })
            .ok_or_else(|| {
                AdacError::CryptoProviderError(format!(
                    "PKCS#11 token with label '{}' was not found",
                    label
                ))
            })?
    } else {
        slots[0]
    };

    // open a session
    let session = pkcs11
        .open_rw_session(slot)
        .map_err(|e| AdacError::CryptoProviderError(format!("Opening PKCS#11 session: {e}")))?;

    // log in the session
    session
        .login(UserType::User, Some(&AuthPin::new(pin.into())))
        .map_err(|e| AdacError::CryptoProviderError(format!("Logging into PKCS#11 token: {e}")))?;

    Ok((pkcs11, slot, session))
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
