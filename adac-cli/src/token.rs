// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput};
use adac::token::{self, AdacToken};
use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
use adac::{KeyOptions, TokenHeader};
use adac_crypto::utils::load_key;
use adac_crypto_pkcs11::Pkcs11Provider;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::ops::DerefMut;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct TokenSignatureReport {
    pub token: String,
    pub path: Option<PathBuf>,
}

impl TokenSignatureReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        if self.path.is_none() {
            writeln!(out, "{}", self.token)?;
        }
        Ok(())
    }
}

pub fn token_sign_command(
    challenge: &String,
    _config: &Option<PathBuf>,
    output: &Option<PathBuf>,
    private: &Option<PathBuf>,
    module: &Option<String>,
    label: &Option<String>,
    permissions: &Option<String>,
    pin: &Option<String>,
    pin_file: &Option<String>,
    pin_env: &Option<String>,
    key_id: &Option<String>,
    key_type: &Option<String>,
    _section: &Option<String>,
) -> anyhow::Result<CommandOutput, CommandError> {
    let challenge = decode_challenge_parameter(challenge)?;

    let (key_type, mut crypto) = load_signing_provider(
        private, module, label, pin, pin_file, pin_env, key_id, key_type,
    )?;

    let (header, extensions) = {
        let mut header = TokenHeader::default();
        header.signature_type = key_type;

        if let Some(permissions) = permissions {
            let permissions = if let Some(hex) = permissions.strip_prefix("0x") {
                hex::decode(hex).map_err(|_| CommandError::AdacError {
                    source: anyhow::anyhow!("Value for 'permissions' is not properly hex encoded."),
                })?
            } else {
                return Err(CommandError::AdacError {
                    source: anyhow::anyhow!("Value for 'permissions' does not start with '0x'."),
                });
            };
            if permissions.len() != 16 {
                return Err(CommandError::AdacError {
                    source: anyhow::anyhow!("Length for 'permissions' is invalid."),
                });
            }

            let requested_permissions =
                u128::from_be_bytes(permissions.as_slice().try_into().unwrap());
            header
                .requested_permissions
                .copy_from_slice(&requested_permissions.to_le_bytes().as_ref());
        }

        let extensions: Vec<u8> = vec![];
        (header, extensions)
    };

    let token = AdacToken::sign(
        key_type,
        header,
        if !extensions.is_empty() {
            Some(extensions.as_slice())
        } else {
            None
        },
        challenge.as_slice(),
        crypto.deref_mut(),
    )
    .map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error signing token: {:?}", e),
    })?;

    if let Some(path) = output {
        let mut file = fs::File::create(path).map_err(|e| CommandError::FileWrite {
            path: path.clone(),
            source: e,
        })?;
        file.write_all(&token.as_slice())
            .map_err(|e| CommandError::FileWrite {
                path: path.clone(),
                source: e,
            })?;
    }

    Ok(CommandOutput::TokenSign(TokenSignatureReport {
        token: BASE64_STANDARD.encode(token.as_slice()),
        path: output.clone(),
    }))
}

fn decode_hex_parameter(value: &str, parameter: &str) -> Result<Vec<u8>, CommandError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(value).map_err(|_| CommandError::InvalidParameter {
        parameter: parameter.to_string(),
    })
}

fn decode_hex_parameter_with_length(
    value: &str,
    parameter: &str,
    expected_len: usize,
) -> Result<Vec<u8>, CommandError> {
    let value = decode_hex_parameter(value, parameter)?;
    if value.len() != expected_len {
        return Err(CommandError::InvalidParameter {
            parameter: parameter.to_string(),
        });
    }
    Ok(value)
}

pub(crate) fn decode_challenge_parameter(value: &str) -> Result<Vec<u8>, CommandError> {
    let value = value
        .strip_prefix("0x")
        .ok_or(CommandError::InvalidParameter {
            parameter: "--challenge".to_string(),
        })?;
    decode_hex_parameter_with_length(value, "--challenge", 32)
}

fn parse_token_key_type(value: &str) -> Result<KeyOptions, CommandError> {
    let key_type = match value {
        "EcdsaP256Sha256" => KeyOptions::EcdsaP256Sha256,
        "EcdsaP384Sha384" => KeyOptions::EcdsaP384Sha384,
        "EcdsaP521Sha512" => KeyOptions::EcdsaP521Sha512,
        "MlDsa44Sha256" => KeyOptions::MlDsa44Sha256,
        "MlDsa65Sha384" => KeyOptions::MlDsa65Sha384,
        "MlDsa87Sha512" => KeyOptions::MlDsa87Sha512,
        "Rsa3072Sha256" => KeyOptions::Rsa3072Sha256,
        "Rsa4096Sha256" => KeyOptions::Rsa4096Sha256,
        "Ed25519Sha512" | "Ed448Shake256" | "SmSm2Sm3" | "CmacAes" | "HmacSha256" => {
            return Err(CommandError::AdacError {
                source: anyhow::anyhow!("Algorithm '{}' not supported for token generation", value),
            });
        }
        _ => {
            return Err(CommandError::AdacError {
                source: anyhow::anyhow!("Algorithm '{}' not recognized", value),
            });
        }
    };

    token::adac_sizes_from_crypto(key_type).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!(
            "Algorithm '{value}' not supported for token generation: {:?}",
            e
        ),
    })?;
    Ok(key_type)
}

fn load_signing_provider(
    private: &Option<PathBuf>,
    module: &Option<String>,
    label: &Option<String>,
    pin: &Option<String>,
    pin_file: &Option<String>,
    pin_env: &Option<String>,
    key_id: &Option<String>,
    key_type: &Option<String>,
) -> Result<(KeyOptions, Box<dyn AdacCryptoProvider>), CommandError> {
    if let Some(key_id) = key_id {
        let key_id = decode_hex_parameter(key_id, "--key-id")?;
        let key_type = key_type.as_ref().ok_or(CommandError::AdacError {
            source: anyhow::anyhow!("Parameter --key-type is required when using --key-id."),
        })?;
        let key_type = parse_token_key_type(key_type)?;

        let module = resolve_pkcs11_module(module)?;
        let label = resolve_pkcs11_label(label);
        let pin = resolve_pkcs11_pin(pin, pin_file, pin_env)?;

        let mut crypto = Pkcs11Provider::new(module, pin, label);
        crypto
            .load_key(key_type, AdacKeyFormat::KeyId, key_id.as_slice())
            .map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error loading PKCS#11 key: {:?}", e),
            })?;

        return Ok((key_type, Box::new(crypto)));
    }

    let private = private.clone().ok_or(CommandError::AdacError {
        source: anyhow::anyhow!("Parameter --private or --key-id required."),
    })?;
    let (detected_key_type, private_key) =
        load_key(private).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error loading key file: {:?}", e),
        })?;
    token::adac_sizes_from_crypto(detected_key_type).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!(
            "Algorithm '{:?}' not supported for token generation: {:?}",
            detected_key_type,
            e
        ),
    })?;

    if let Some(expected_key_type) = key_type {
        let expected_key_type = parse_token_key_type(expected_key_type)?;
        if expected_key_type != detected_key_type {
            return Err(CommandError::AdacError {
                source: anyhow::anyhow!(
                    "Key type '{:?}' does not match private key type '{:?}'",
                    expected_key_type,
                    detected_key_type
                ),
            });
        }
    }

    let mut crypto = adac_crypto_rust::RustCryptoProvider::default();
    crypto
        .load_key(
            detected_key_type,
            AdacKeyFormat::Pkcs8,
            private_key.as_slice(),
        )
        .map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error parsing PKCS#8 key: {:?}", e),
        })?;

    Ok((detected_key_type, Box::new(crypto)))
}

fn resolve_pkcs11_module(module: &Option<String>) -> Result<String, CommandError> {
    if let Some(module) = module {
        Ok(module.clone())
    } else if let Ok(module) = std::env::var("PKCS11_MODULE") {
        Ok(module)
    } else {
        Err(CommandError::AdacError {
            source: anyhow::anyhow!("Parameter --module is required."),
        })
    }
}

fn resolve_pkcs11_label(label: &Option<String>) -> Option<String> {
    if let Some(label) = label {
        Some(label.clone())
    } else {
        std::env::var("PKCS11_SLOT").ok()
    }
}

fn resolve_pkcs11_pin(
    pin: &Option<String>,
    pin_file: &Option<String>,
    pin_env: &Option<String>,
) -> Result<String, CommandError> {
    if let Some(pin) = pin {
        Ok(pin.clone())
    } else if let Some(pin_file) = pin_file {
        fs::read_to_string(pin_file).map_err(|e| CommandError::FileRead {
            path: pin_file.clone().into(),
            source: e,
        })
    } else if let Some(pin_env) = pin_env {
        std::env::var(pin_env).map_err(|_| CommandError::AdacError {
            source: anyhow::anyhow!("Environment variable {} not set", pin_env),
        })
    } else if let Ok(pin) = std::env::var("PKCS11_PIN") {
        Ok(pin)
    } else {
        Err(CommandError::AdacError {
            source: anyhow::anyhow!("Parameter --pin or --pin-env or --pin-file is required."),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared;
    use adac_crypto::utils::get_public_key;

    const TOKEN_CHALLENGE: &str =
        "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn fixture_key_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../adac-tests/resources/keys")
            .join(name)
    }

    #[test]
    fn token_sign_command_generates_verifiable_token() {
        let dir = shared::make_temp_dir("adac-cli-token-tests");
        let private = fixture_key_path("EcdsaP384Key-0.pk8");
        let challenge = TOKEN_CHALLENGE.to_string();

        let output = token_sign_command(
            &challenge,
            &None,
            &None,
            &Some(private.clone()),
            &None,
            &None,
            &Some("0x0000000003FFFFFFFFFFFFFF00000000".to_string()),
            &None,
            &None,
            &None,
            &None,
            &None,
            &Some("token".to_string()),
        )
        .unwrap();

        let CommandOutput::TokenSign(report) = output else {
            panic!("unexpected command output");
        };
        let token = AdacToken::from_bytes(BASE64_STANDARD.decode(report.token).unwrap()).unwrap();
        let (key_type, private_key) = load_key(private).unwrap();
        let public_key = get_public_key(key_type, &private_key).unwrap();
        let crypto = adac_crypto_rust::RustCryptoProvider::default();
        let challenge = decode_hex_parameter(&challenge, "--challenge").unwrap();

        token
            .verify(public_key.as_slice(), challenge.as_slice(), &crypto)
            .unwrap();

        let header = *token.header();
        assert_eq!(header.format_version.major, 1);
        assert_eq!(header.format_version.minor, 0);
        assert_eq!(
            header.requested_permissions,
            0x0000000003FFFFFFFFFFFFFF00000000u128.to_le_bytes()
        );

        let _ = fs::remove_dir_all(dir);
    }
}
