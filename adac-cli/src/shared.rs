// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::CommandError;
use adac::KeyOptions;

pub fn parse_cli_key_type(value: &str) -> Result<KeyOptions, CommandError> {
    match value {
        "EcdsaP256Sha256" => Ok(KeyOptions::EcdsaP256Sha256),
        "EcdsaP384Sha384" => Ok(KeyOptions::EcdsaP384Sha384),
        "EcdsaP521Sha512" => Ok(KeyOptions::EcdsaP521Sha512),
        "Rsa3072Sha256" => Ok(KeyOptions::Rsa3072Sha256),
        "Rsa4096Sha256" => Ok(KeyOptions::Rsa4096Sha256),
        "Ed25519Sha512" => Ok(KeyOptions::Ed25519Sha512),
        "Ed448Shake256" => Ok(KeyOptions::Ed448Shake256),
        "SmSm2Sm3" => Ok(KeyOptions::SmSm2Sm3),
        "CmacAes" => Ok(KeyOptions::CmacAes),
        "HmacSha256" => Ok(KeyOptions::HmacSha256),
        "MlDsa44Sha256" => Ok(KeyOptions::MlDsa44Sha256),
        "MlDsa65Sha384" => Ok(KeyOptions::MlDsa65Sha384),
        "MlDsa87Sha512" => Ok(KeyOptions::MlDsa87Sha512),
        _ => Err(CommandError::AdacError {
            source: anyhow::anyhow!("Algorithm '{}' not recognized", value),
        }),
    }
}
