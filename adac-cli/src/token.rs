// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput, config, shared};
use adac::token::{self, AdacToken};
use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
use adac::{AdacError, KeyOptions, TokenHeader};
use adac_crypto::utils::{convert_signature, load_certificates, load_key};
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
    challenge: &str,
    config: &Option<PathBuf>,
    output: &Option<PathBuf>,
    chain: &Option<PathBuf>,
    private_key: &Option<PathBuf>,
    module: &Option<String>,
    slot: &Option<String>,
    permissions: &Option<String>,
    pin: &Option<shared::PinSecret>,
    pin_file: &Option<String>,
    pin_env: &Option<String>,
    key_id: &Option<String>,
    key_type: &Option<String>,
    section: &Option<String>,
) -> anyhow::Result<CommandOutput, CommandError> {
    let config =
        if let Some(config) = config {
            let config = fs::read_to_string(config).map_err(|e| CommandError::FileRead {
                path: config.clone(),
                source: e,
            })?;
            let config = config::parse_adac_token_configuration(&config, (*section).clone())
                .map_err(|e| CommandError::AdacError {
                    source: anyhow::anyhow!("Error parsing configuration file: {:?}", e),
                })?;
            Some(config)
        } else {
            None
        };
    let challenge = decode_challenge_parameter(challenge)?;

    let (key_type, mut crypto) = load_signing_provider(
        private_key,
        module,
        slot,
        pin,
        pin_file,
        pin_env,
        key_id,
        key_type,
    )?;

    let (header, extensions) = if let Some(config) = config {
        let mut header = build_token_header(&config, key_type);
        if let Some(permissions) = permissions {
            header.requested_permissions = parse_requested_permissions_parameter(permissions)?;
        }
        (header, config.extensions.clone())
    } else {
        let mut header = TokenHeader {
            signature_type: key_type,
            ..Default::default()
        };

        if let Some(permissions) = permissions {
            header.requested_permissions = parse_requested_permissions_parameter(permissions)?;
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

    verify_token_if_chain_is_provided(chain, &token, challenge.as_slice())?;

    if let Some(path) = output {
        let mut file = fs::File::create(path).map_err(|e| CommandError::FileWrite {
            path: path.clone(),
            source: e,
        })?;
        file.write_all(token.as_slice())
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

#[derive(Debug, Serialize)]
pub struct TokenPrepareReport {
    pub token: String,
    pub tbs: String,
    pub hash: String,
    pub token_path: Option<PathBuf>,
    pub tbs_path: Option<PathBuf>,
    pub hash_path: Option<PathBuf>,
}

impl TokenPrepareReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        if self.token_path.is_none() {
            writeln!(out, "{}", self.token)?;
        }
        if self.tbs_path.is_none() {
            writeln!(out, "TBS={}", self.tbs)?;
        }
        if self.hash_path.is_none() {
            writeln!(out, "Hash={}", self.hash)?;
        }
        Ok(())
    }
}

pub fn token_prepare_command(
    config: &Option<PathBuf>,
    key_type: &str,
    challenge: &str,
    permissions: &Option<String>,
    section: &Option<String>,
    token_path: &Option<PathBuf>,
    tbs_path: &Option<PathBuf>,
    hash_path: &Option<PathBuf>,
) -> anyhow::Result<CommandOutput, CommandError> {
    let config =
        if let Some(config) = config {
            let config = fs::read_to_string(config).map_err(|e| CommandError::FileRead {
                path: config.clone(),
                source: e,
            })?;
            let config = config::parse_adac_token_configuration(&config, (*section).clone())
                .map_err(|e| CommandError::AdacError {
                    source: anyhow::anyhow!("Error parsing configuration file: {:?}", e),
                })?;
            Some(config)
        } else {
            None
        };

    let key_type = parse_token_key_type(key_type)?;
    let challenge = decode_challenge_parameter(challenge)?;

    let (header, extensions) = if let Some(config) = config {
        let mut header = build_token_header(&config, key_type);
        if let Some(permissions) = permissions {
            header.requested_permissions = parse_requested_permissions_parameter(permissions)?;
        }
        (header, config.extensions.clone())
    } else {
        let mut header = TokenHeader {
            signature_type: key_type,
            ..Default::default()
        };

        if let Some(permissions) = permissions {
            header.requested_permissions = parse_requested_permissions_parameter(permissions)?;
        }

        let extensions: Vec<u8> = vec![];
        (header, extensions)
    };

    let mut crypto = PrepareCryptoProvider::new(key_type);
    let token = AdacToken::sign(
        key_type,
        header,
        if !extensions.is_empty() {
            Some(extensions.as_slice())
        } else {
            None
        },
        challenge.as_slice(),
        &mut crypto,
    )
    .map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error preparing token for signing: {:?}", e),
    })?;

    write_output(token_path, token.as_slice())?;
    write_output(tbs_path, crypto.tbs.as_slice())?;
    write_output(hash_path, crypto.hash.as_slice())?;

    Ok(CommandOutput::TokenOfflinePrepare(TokenPrepareReport {
        token: BASE64_STANDARD.encode(token.as_slice()),
        tbs: BASE64_STANDARD.encode(crypto.tbs.as_slice()),
        hash: base16ct::lower::encode_string(crypto.hash.as_slice()),
        token_path: token_path.clone(),
        tbs_path: tbs_path.clone(),
        hash_path: hash_path.clone(),
    }))
}

#[derive(Debug, Serialize)]
pub struct TokenMergeReport {
    pub token: String,
    pub path: Option<PathBuf>,
}

impl TokenMergeReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        if self.path.is_none() {
            writeln!(out, "{}", self.token)?;
        }
        Ok(())
    }
}

pub fn token_merge_command(
    input: &PathBuf,
    signature: &PathBuf,
    output: &Option<PathBuf>,
    challenge: &Option<String>,
    chain: &Option<PathBuf>,
) -> anyhow::Result<CommandOutput, CommandError> {
    let token = load_token(input).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error loading token: {:?}", e),
    })?;
    let signature = fs::read(signature).map_err(|e| CommandError::FileRead {
        path: signature.clone(),
        source: e,
    })?;

    let key_type = token.header().signature_type;
    let signature = normalize_detached_signature(key_type, signature.as_slice())?;
    let (_, sig_size) =
        token::adac_sizes_from_crypto(key_type).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error determining signature size: {:?}", e),
        })?;

    let sig_offset = token.get_tbs().len();
    let mut merged = token.to_bytes();
    merged[sig_offset..(sig_offset + sig_size)].copy_from_slice(signature.as_slice());

    let token = AdacToken::from_bytes(merged).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error rebuilding token: {:?}", e),
    })?;

    if chain.is_some() {
        let Some(challenge) = challenge else {
            return Err(CommandError::InvalidParameter {
                parameter: "--challenge".to_string(),
            });
        };
        let challenge = decode_challenge_parameter(challenge)?;
        verify_token_if_chain_is_provided(chain, &token, challenge.as_slice())?;
    }

    write_output(output, token.as_slice())?;

    Ok(CommandOutput::TokenOfflineMerge(TokenMergeReport {
        token: BASE64_STANDARD.encode(token.as_slice()),
        path: output.clone(),
    }))
}

fn verify_token_if_chain_is_provided(
    chain: &Option<PathBuf>,
    token: &AdacToken,
    challenge: &[u8],
) -> Result<(), CommandError> {
    if let Some(path) = chain {
        let chain = load_certificates(path).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
        })?;
        shared::verify_token_signed_by_last_certificate(chain.as_slice(), token, challenge)?;
    }
    Ok(())
}

fn build_token_header(config: &config::AdacTokenConfig, key_type: KeyOptions) -> TokenHeader {
    TokenHeader {
        format_version: config.format_version,
        signature_type: key_type,
        requested_permissions: config.requested_permissions,
        ..Default::default()
    }
}

pub fn load_token<P: AsRef<std::path::Path>>(path: P) -> Result<AdacToken, AdacError> {
    let contents = fs::read(path).map_err(|e| AdacError::InputOutput(e.to_string()))?;
    read_token(contents.as_slice())
}

pub fn read_token(contents: &[u8]) -> Result<AdacToken, AdacError> {
    let bytes = if let Ok(pem) = pem::parse(contents) {
        if pem.tag().eq("ADAC TOKEN") {
            pem.contents().to_vec()
        } else {
            contents.to_vec()
        }
    } else {
        contents.to_vec()
    };

    match AdacToken::from_bytes(bytes) {
        Ok(token) => Ok(token),
        Err(raw_error) => {
            if let Ok(text) = std::str::from_utf8(contents) {
                let decoded = BASE64_STANDARD
                    .decode(text.trim())
                    .map_err(|e| AdacError::Encoding(e.to_string()))?;
                AdacToken::from_bytes(decoded)
            } else {
                Err(raw_error)
            }
        }
    }
}

fn write_output(path: &Option<PathBuf>, contents: &[u8]) -> Result<(), CommandError> {
    if let Some(path) = path {
        let mut file = fs::File::create(path).map_err(|e| CommandError::FileWrite {
            path: path.clone(),
            source: e,
        })?;
        file.write_all(contents)
            .map_err(|e| CommandError::FileWrite {
                path: path.clone(),
                source: e,
            })?;
    }

    Ok(())
}

pub(crate) fn decode_challenge_parameter(value: &str) -> Result<Vec<u8>, CommandError> {
    shared::decode_base16_parameter_with_length(value, "--challenge", 32)
}

fn parse_token_key_type(value: &str) -> Result<KeyOptions, CommandError> {
    let key_type = shared::parse_cli_key_type(value)?;
    token::adac_sizes_from_crypto(key_type).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!(
            "Algorithm '{value}' not supported for token generation: {:?}",
            e
        ),
    })?;
    Ok(key_type)
}

fn parse_requested_permissions_parameter(value: &str) -> Result<[u8; 16], CommandError> {
    let permissions = shared::decode_hex_integer_parameter_with_length(value, "PERMISSIONS", 16)?;
    let permissions = u128::from_be_bytes(permissions.as_slice().try_into().unwrap());
    Ok(permissions.to_le_bytes())
}

fn load_signing_provider(
    private_key: &Option<PathBuf>,
    module: &Option<String>,
    slot: &Option<String>,
    pin: &Option<shared::PinSecret>,
    pin_file: &Option<String>,
    pin_env: &Option<String>,
    key_id: &Option<String>,
    key_type: &Option<String>,
) -> Result<(KeyOptions, Box<dyn AdacCryptoProvider>), CommandError> {
    if let Some(key_id) = key_id {
        let key_id = shared::decode_base16_parameter(key_id, "--key-id")?;
        let key_type = key_type.as_ref().ok_or(CommandError::AdacError {
            source: anyhow::anyhow!("Parameter --key-type is required when using --key-id."),
        })?;
        let key_type = parse_token_key_type(key_type)?;

        let module = resolve_pkcs11_module(module)?;
        let slot = resolve_pkcs11_slot(slot);
        let pin = shared::resolve_pkcs11_pin(pin, pin_file, pin_env)?;

        let mut crypto = shared::create_pkcs11_provider(module, pin, slot)?;
        crypto
            .load_key(key_type, AdacKeyFormat::KeyId, key_id.as_slice())
            .map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error loading PKCS#11 key: {:?}", e),
            })?;

        return Ok((key_type, Box::new(crypto)));
    }

    let private_key = private_key.clone().ok_or(CommandError::AdacError {
        source: anyhow::anyhow!("Parameter --private-key or --key-id required."),
    })?;
    let (detected_key_type, private_key) =
        load_key(private_key).map_err(|e| CommandError::AdacError {
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

fn resolve_pkcs11_slot(slot: &Option<String>) -> Option<String> {
    if let Some(slot) = slot {
        Some(slot.clone())
    } else {
        std::env::var("PKCS11_SLOT").ok()
    }
}

fn normalize_detached_signature(
    key_type: KeyOptions,
    signature: &[u8],
) -> Result<Vec<u8>, CommandError> {
    let (_, sig_size) =
        token::adac_sizes_from_crypto(key_type).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error determining signature size: {:?}", e),
        })?;
    if signature.len() == sig_size {
        return Ok(signature.to_vec());
    }

    convert_signature(key_type, signature).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error parsing signature: {:?}", e),
    })
}

struct PrepareCryptoProvider {
    key_type: KeyOptions,
    hash: Vec<u8>,
    tbs: Vec<u8>,
}

impl PrepareCryptoProvider {
    fn new(key_type: KeyOptions) -> Self {
        Self {
            key_type,
            hash: vec![],
            tbs: vec![],
        }
    }
}

impl AdacCryptoProvider for PrepareCryptoProvider {
    fn verify(
        &self,
        key_type: KeyOptions,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), adac::AdacError> {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();
        crypto.verify(key_type, public_key, data, signature)
    }

    fn hash(&self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, adac::AdacError> {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();
        crypto.hash(key_type, data)
    }

    fn sign(&mut self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, adac::AdacError> {
        if self.key_type != key_type {
            return Err(adac::AdacError::InconsistentCrypto);
        }

        let (_, sig_size) = token::adac_sizes_from_crypto(key_type)?;
        self.tbs = data.to_vec();
        self.hash = self.hash(key_type, data)?;

        Ok(vec![0u8; sig_size])
    }

    fn load_key(
        &mut self,
        key_type: KeyOptions,
        format: AdacKeyFormat,
        key: &[u8],
    ) -> Result<Vec<u8>, adac::AdacError> {
        let mut crypto = adac_crypto_rust::RustCryptoProvider::default();
        crypto.load_key(key_type, format, key)
    }
}
