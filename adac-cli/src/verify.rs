// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput, token};
use adac::CertificateUsage;
use adac_crypto::encoding::{
    EncodingIssue, EncodingValidationPolicy, validate_certificate_chain_with_policy,
    validate_token_with_policy,
};
use adac_crypto::public::AdacPublicKey;
use adac_crypto::utils::{read_certificate_chain_bytes, read_certificates};
use adac_crypto::validation::{ChainValidationPolicy, ChainValidator};
use serde::Serialize;
use sha2::Digest;
use sha2::digest::Update;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub encoding_errors: Vec<EncodingVerification>,
    pub certificates: Vec<CertificateVerification>,
    pub token: Option<TokenVerification>,
    pub summary: Vec<String>,
    pub error_count: u64,
}

impl VerificationReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        for error in &self.encoding_errors {
            writeln!(
                out,
                "Encoding error at {}, offset {}: {}",
                error.context, error.offset, error.message
            )?;
        }
        for (i, crt) in self.certificates.iter().enumerate() {
            writeln!(out, "Certificate {}: Key ID {}", i, crt.key_id)?;
            for e in &crt.errors {
                writeln!(out, "Error at level {}: {}", i, e)?;
            }
        }
        if let Some(token) = &self.token {
            if token.signature_verified {
                writeln!(out, "Token signature verified")?;
            }
            if token.signature_verified && token.errors.is_empty() && self.error_count == 0 {
                writeln!(out, "Token verified")?;
            }
            for error in &token.errors {
                writeln!(out, "Token error: {}", error)?;
            }
        }
        for s in &self.summary {
            writeln!(out, "{}", s)?;
        }
        if self.error_count > 0 {
            writeln!(out)?;
            writeln!(
                out,
                "{} error(s) found during verification",
                self.error_count
            )?;
        }

        Ok(())
    }

    pub fn error_code(&self) -> i32 {
        if self.error_count > 0 { 1 } else { 0 }
    }
}

#[derive(Debug, Serialize)]
pub struct EncodingVerification {
    pub offset: usize,
    pub context: String,
    pub message: String,
}

impl From<EncodingIssue> for EncodingVerification {
    fn from(issue: EncodingIssue) -> Self {
        Self {
            offset: issue.offset,
            context: issue.context,
            message: issue.message,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CertificateVerification {
    pub key_id: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenVerification {
    pub signature_verified: bool,
    pub errors: Vec<String>,
}

pub fn verify_command(
    path: &PathBuf,
    token: &Option<PathBuf>,
    challenge: &Option<String>,
    strict: bool,
) -> anyhow::Result<CommandOutput, CommandError> {
    let verify_token = token.is_some();
    let contents = std::fs::read_to_string(path).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error reading certificate chain: {:?}", e),
    })?;
    let certificate_chain_bytes =
        read_certificate_chain_bytes(contents.as_str()).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error decoding certificate chain: {:?}", e),
        })?;
    let encoding_policy = EncodingValidationPolicy {
        reject_critical_extensions: strict,
    };
    let mut encoding_errors =
        validate_certificate_chain_with_policy(certificate_chain_bytes.as_slice(), encoding_policy)
            .into_iter()
            .map(EncodingVerification::from)
            .collect::<Vec<_>>();

    let chain = match read_certificates(contents) {
        Ok(chain) => chain,
        Err(e) if !encoding_errors.is_empty() => {
            return Ok(CommandOutput::Verify(VerificationReport {
                error_count: encoding_errors.len() as u64,
                encoding_errors,
                certificates: Vec::new(),
                token: None,
                summary: Vec::new(),
            }));
        }
        Err(e) => {
            return Err(CommandError::AdacError {
                source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
            });
        }
    };

    if chain.is_empty() {
        return Err(CommandError::AdacError {
            source: anyhow::anyhow!("Empty certificate chain"),
        });
    }

    if (token.is_some() || challenge.is_some()) && (token.is_none() || challenge.is_none()) {
        return Err(CommandError::AdacError {
            source: anyhow::anyhow!("Parameter --token and --challenge must be provided together."),
        });
    }

    let token = if let Some(token) = token {
        let contents = std::fs::read(token).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error loading token: {:?}", e),
        })?;
        encoding_errors.extend(
            validate_token_with_policy(contents.as_slice(), encoding_policy)
                .into_iter()
                .map(EncodingVerification::from),
        );
        Some(contents)
    } else {
        None
    };

    let challenge = if let Some(challenge) = challenge {
        Some(token::decode_challenge_parameter(challenge)?)
    } else {
        None
    };

    let mut error_count = encoding_errors.len() as u64;
    let crypto = adac_crypto_rust::RustCryptoProvider::default();
    let validation_policy = ChainValidationPolicy {
        require_leaf_last: strict && verify_token,
    };
    let mut validator = ChainValidator::with_policy(validation_policy, &crypto);

    let mut certificates = vec![];

    for (i, current) in chain.iter().enumerate() {
        let header = current.header();
        let public_key = AdacPublicKey::from_adac(header.key_type, current.get_public_key())
            .map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error parsing public key at level {}: {:?}", i, e),
            })?;
        let key_id = sha2::Sha256::new().chain(public_key.get_spki()).finalize();
        let key_id = base16ct::lower::encode_string(key_id.as_slice());

        validator.push_certificate(current);
        certificates.push(CertificateVerification {
            key_id,
            errors: Vec::new(),
        });
    }

    let mut token_effective_permissions = None;
    let mut token_effective_soc_id = None;
    let mut token = if let (Some(token), Some(challenge)) = (token, challenge) {
        let token = token::read_token(token.as_slice()).map_err(|e| {
            error_count += 1;
            CommandError::AdacError {
                source: anyhow::anyhow!("Error parsing token: {:?}", e),
            }
        })?;
        let token_result = validator.validate_token(&token, challenge.as_slice());
        let errors = token_result
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let signature_verified = errors.is_empty();
        error_count += errors.len() as u64;
        token_effective_permissions = token_result.effective_permissions;
        token_effective_soc_id = token_result.effective_soc_id;
        Some(TokenVerification {
            signature_verified,
            errors,
        })
    } else {
        None
    };

    let validation = validator.finish();
    error_count += validation.chain_errors.len() as u64;
    let chain_error_count = validation.chain_errors.len()
        + validation
            .certificates
            .iter()
            .map(|certificate| certificate.errors.len())
            .sum::<usize>();
    for certificate in &validation.certificates {
        let errors = certificate
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        error_count += errors.len() as u64;
        certificates[certificate.index].errors = errors;
    }
    if let Some(token) = &mut token
        && token.signature_verified
        && chain_error_count != 0
    {
        token.errors.push(
            "Token signature verifies, but token validation failed because the certificate chain is invalid"
                .to_string(),
        );
        error_count += 1;
    }

    let permissions = token_effective_permissions.unwrap_or(validation.effective.permissions);

    let mut summary = vec![];
    for error in validation.chain_errors {
        summary.push(error.to_string());
    }

    let usage = validation.effective.usage;
    let lifecycle = validation.effective.lifecycle;
    let oem_constraint = validation.effective.oem_constraint;
    let soc_id = token_effective_soc_id.unwrap_or(validation.effective.soc_id);
    let soc_class = validation.effective.soc_class;
    let policies = validation.effective.policies;

    if soc_id != [0x0u8; 16] {
        let mut id = [0x0u8; 16];
        id.copy_from_slice(u128::from_le_bytes(soc_id).to_be_bytes().as_ref());
        summary.push(format!(
            "Restricted to SoC ID: 0x{} ({})",
            base16ct::lower::encode_string(id.as_slice()),
            base16ct::lower::encode_string(soc_id.as_slice())
        ));
    }
    if soc_class != 0x0 {
        summary.push(format!("Restricted to SoC Class: 0x{:x}", soc_class));
    }
    if lifecycle != 0 {
        summary.push(format!("Restricted to lifecycle 0x{:x}", lifecycle));
    }
    if oem_constraint != 0 {
        summary.push(format!(
            "Restricted to OEM constraint 0x{:x}",
            oem_constraint
        ));
    }

    if usage != CertificateUsage::AdacUsageNeutral {
        summary.push(format!("Restricted to usage {:?}", usage));
    }
    if policies != 0 {
        summary.push(format!("Effective policies: 0x{:x}", policies));
    }

    let mut effective = [0x00u8; 16];
    effective.copy_from_slice(u128::from_le_bytes(permissions).to_be_bytes().as_ref());
    summary.push(format!(
        "Effective permissions: 0x{} ({})",
        base16ct::lower::encode_string(effective.as_slice()),
        base16ct::lower::encode_string(permissions.as_slice())
    ));
    Ok(CommandOutput::Verify(VerificationReport {
        encoding_errors,
        certificates,
        token,
        summary,
        error_count,
    }))
}
