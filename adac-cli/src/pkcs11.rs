// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput, shared};
use adac::KeyOptions::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::Serialize;
use std::io::Write;

#[derive(Debug, Serialize)]
pub struct Pkcs11GenerateReport {
    kid: String,
    public_key: String,
    pem: String,
}

impl Pkcs11GenerateReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        writeln!(out, "Key '{}' generated", self.kid)?;
        writeln!(out, "Public-key = {}", self.public_key)?;
        writeln!(out)?;
        writeln!(out, "{}", self.pem)?;
        Ok(())
    }
}

fn parse_pkcs11_keygen_key_type(value: &str) -> Result<adac::KeyOptions, CommandError> {
    let key_type = shared::parse_cli_key_type(value)?;
    match key_type {
        EcdsaP256Sha256 | EcdsaP384Sha384 | EcdsaP521Sha512 | Rsa3072Sha256 | Rsa4096Sha256 => {
            Ok(key_type)
        }
        _ => Err(CommandError::AdacError {
            source: anyhow::anyhow!("Algorithm '{}' not supported", value),
        }),
    }
}

pub fn pkcs11_generate_command(
    key_type: &str,
    module: &Option<String>,
    slot: &Option<String>,
    pin: &Option<String>,
    pin_file: &Option<String>,
    pin_env: &Option<String>,
) -> anyhow::Result<CommandOutput, CommandError> {
    let key_type = parse_pkcs11_keygen_key_type(key_type)?;

    let module = if let Some(m) = module {
        m.clone()
    } else if let Ok(m) = std::env::var("PKCS11_MODULE") {
        m
    } else {
        return Err(CommandError::AdacError {
            source: anyhow::anyhow!("Parameter --module is required."),
        });
    };

    let slot = if let Some(slot) = slot {
        Some(slot.clone())
    } else {
        std::env::var("PKCS11_SLOT").ok()
    };

    let pin = if let Some(p) = pin {
        p.clone()
    } else if let Some(p) = pin_file {
        std::fs::read_to_string(p).map_err(|e| CommandError::FileRead {
            path: p.clone().into(),
            source: e,
        })?
    } else if let Some(env) = pin_env {
        std::env::var(env).map_err(|_| CommandError::AdacError {
            source: anyhow::anyhow!("Environment variable {} not set", env),
        })?
    } else if let Ok(p) = std::env::var("PKCS11_PIN") {
        p
    } else {
        return Err(CommandError::AdacError {
            source: anyhow::anyhow!("Parameter --pin or --pin-env or --pin-file is required."),
        });
    };

    let mut crypto = shared::create_pkcs11_provider(module, pin, slot)?;
    let (kid, _, spki, _, _) =
        crypto
            .generate_key(key_type)
            .map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error generating PKCS#11 key: {:?}", e),
            })?;

    let public_key = BASE64_STANDARD.encode(&spki);
    let pem_config = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
    let pem = pem::Pem::new("PUBLIC KEY", spki.as_slice());
    let pem = pem::encode_config(&pem, pem_config);

    Ok(CommandOutput::Pkcs11Generate(Pkcs11GenerateReport {
        kid,
        public_key,
        pem,
    }))
}
