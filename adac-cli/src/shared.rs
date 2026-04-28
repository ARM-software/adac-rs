// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::CommandError;
use adac::KeyOptions;
use adac::certificate::AdacCertificate;
use adac::token::AdacToken;
use adac_crypto_pkcs11::Pkcs11Provider;
use std::convert::Infallible;
use std::fmt;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct PinSecret(Zeroizing<String>);

impl PinSecret {
    pub(crate) fn expose_clone(&self) -> Zeroizing<String> {
        self.0.clone()
    }
}

impl std::str::FromStr for PinSecret {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(Zeroizing::new(value.to_string())))
    }
}

impl fmt::Debug for PinSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

pub(crate) fn decode_base16_parameter(
    value: &str,
    parameter: &str,
) -> Result<Vec<u8>, CommandError> {
    if value.starts_with("0x") || value.starts_with("0X") {
        return Err(CommandError::InvalidParameter {
            parameter: parameter.to_string(),
        });
    }

    hex::decode(value).map_err(|_| CommandError::InvalidParameter {
        parameter: parameter.to_string(),
    })
}

pub(crate) fn decode_base16_parameter_with_length(
    value: &str,
    parameter: &str,
    expected_len: usize,
) -> Result<Vec<u8>, CommandError> {
    let value = decode_base16_parameter(value, parameter)?;
    if value.len() != expected_len {
        return Err(CommandError::InvalidParameter {
            parameter: parameter.to_string(),
        });
    }
    Ok(value)
}

pub(crate) fn decode_hex_integer_parameter_with_length(
    value: &str,
    parameter: &str,
    expected_len: usize,
) -> Result<Vec<u8>, CommandError> {
    let Some(value) = value.strip_prefix("0x") else {
        return Err(CommandError::InvalidParameter {
            parameter: parameter.to_string(),
        });
    };

    let value = hex::decode(value).map_err(|_| CommandError::InvalidParameter {
        parameter: parameter.to_string(),
    })?;
    if value.len() != expected_len {
        return Err(CommandError::InvalidParameter {
            parameter: parameter.to_string(),
        });
    }
    Ok(value)
}

pub(crate) fn create_pkcs11_provider(
    module: String,
    pin: Zeroizing<String>,
    slot: Option<String>,
) -> Result<Pkcs11Provider, CommandError> {
    Pkcs11Provider::new(module, pin, slot).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error creating PKCS#11 session: {:?}", e),
    })
}

pub(crate) fn resolve_pkcs11_pin(
    pin: &Option<PinSecret>,
    pin_file: &Option<String>,
    pin_env: &Option<String>,
) -> Result<Zeroizing<String>, CommandError> {
    if let Some(pin) = pin {
        Ok(pin.expose_clone())
    } else if let Some(pin_file) = pin_file {
        std::fs::read_to_string(pin_file)
            .map(Zeroizing::new)
            .map_err(|e| CommandError::FileRead {
                path: PathBuf::from(pin_file),
                source: e,
            })
    } else if let Some(pin_env) = pin_env {
        std::env::var(pin_env)
            .map(Zeroizing::new)
            .map_err(|_| CommandError::AdacError {
                source: anyhow::anyhow!("Environment variable {} not set", pin_env),
            })
    } else if let Ok(pin) = std::env::var("PKCS11_PIN") {
        Ok(Zeroizing::new(pin))
    } else {
        Err(CommandError::AdacError {
            source: anyhow::anyhow!("Parameter --pin or --pin-env or --pin-file is required."),
        })
    }
}

pub(crate) fn verify_certificate_signed_by_issuer(
    issuer_chain: &[AdacCertificate],
    certificate: &AdacCertificate,
) -> Result<(), CommandError> {
    let Some(issuer) = issuer_chain.last() else {
        return Err(CommandError::AdacError {
            source: anyhow::anyhow!("Issuer certificate chain is empty."),
        });
    };

    let crypto = adac_crypto_rust::RustCryptoProvider::default();
    certificate
        .verify(issuer.get_public_key(), &crypto)
        .map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!(
                "New certificate does not verify against issuer chain: {:?}",
                e
            ),
        })
}

pub(crate) fn verify_token_signed_by_last_certificate(
    chain: &[AdacCertificate],
    token: &AdacToken,
    challenge: &[u8],
) -> Result<(), CommandError> {
    let Some(signer) = chain.last() else {
        return Err(CommandError::AdacError {
            source: anyhow::anyhow!("Certificate chain is empty."),
        });
    };

    let crypto = adac_crypto_rust::RustCryptoProvider::default();
    token
        .verify(signer.get_public_key(), challenge, &crypto)
        .map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!(
                "Token does not verify against the last certificate in the chain: {:?}",
                e
            ),
        })
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_base16_parameter_accepts_plain_base16() {
        assert_eq!(
            decode_base16_parameter("A0ff", "--key-id").unwrap(),
            vec![0xA0, 0xFF]
        );
    }

    #[test]
    fn decode_base16_parameter_rejects_hex_prefix() {
        assert!(matches!(
            decode_base16_parameter("0xA0ff", "--key-id"),
            Err(CommandError::InvalidParameter { parameter }) if parameter == "--key-id"
        ));
        assert!(matches!(
            decode_base16_parameter("0XA0ff", "--key-id"),
            Err(CommandError::InvalidParameter { parameter }) if parameter == "--key-id"
        ));
    }

    #[test]
    fn decode_hex_integer_parameter_requires_lowercase_prefix() {
        assert_eq!(
            decode_hex_integer_parameter_with_length("0xA0ff", "PERMISSIONS", 2).unwrap(),
            vec![0xA0, 0xFF]
        );
        assert!(matches!(
            decode_hex_integer_parameter_with_length("A0ff", "PERMISSIONS", 2),
            Err(CommandError::InvalidParameter { parameter }) if parameter == "PERMISSIONS"
        ));
        assert!(matches!(
            decode_hex_integer_parameter_with_length("0XA0ff", "PERMISSIONS", 2),
            Err(CommandError::InvalidParameter { parameter }) if parameter == "PERMISSIONS"
        ));
    }
}
