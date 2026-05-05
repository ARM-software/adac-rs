// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::{
    CertificateRole, CertificateUsage, KeyOptions, certificate::AdacCertificate, token::AdacToken,
    traits::AdacCryptoProvider,
};
use std::fmt;

/// Chain-validation behavior knobs.
///
/// The default policy accepts chains that do not terminate in a Leaf certificate
/// while still reporting whether the terminal certificate is a Leaf.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct ChainValidationPolicy {
    pub require_leaf_last: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationIssue {
    EmptyChain,
    FirstCertificateNotRoot,
    RootAfterFirst,
    LeafBeforeLast,
    MissingLeafLast,
    UsageMismatch {
        previous: CertificateUsage,
        current: CertificateUsage,
    },
    SocIdMismatch {
        previous: [u8; 16],
        current: [u8; 16],
    },
    SocClassMismatch {
        previous: u32,
        current: u32,
    },
    LifecycleMismatch {
        previous: u16,
        current: u16,
    },
    OemConstraintMismatch {
        previous: u16,
        current: u16,
    },
    SignatureVerificationFailed {
        source: String,
    },
    TokenKeyTypeMismatch,
    TokenVerificationFailed {
        source: String,
    },
}

impl ValidationIssue {
    pub fn message(&self) -> String {
        match self {
            Self::EmptyChain => "Certificate chain is empty".to_string(),
            Self::FirstCertificateNotRoot => {
                "First certificate does not have Root role".to_string()
            }
            Self::RootAfterFirst => "Only first certificate can have root role".to_string(),
            Self::LeafBeforeLast => "Only last certificate can have leaf role".to_string(),
            Self::MissingLeafLast => "Last certificate does not have Leaf role".to_string(),
            Self::UsageMismatch { previous, current } => {
                format!("Usage mismatch was {previous:?} now {current:?}")
            }
            Self::SocIdMismatch { previous, current } => {
                format!("SoC ID does not match ({previous:?} != {current:?})")
            }
            Self::SocClassMismatch { previous, current } => {
                format!("SoC ID Class not match (0x{previous:x} != 0x{current:x})")
            }
            Self::LifecycleMismatch { previous, current } => {
                format!("Lifecycle does not match (0x{previous:x} != 0x{current:x})")
            }
            Self::OemConstraintMismatch { previous, current } => {
                format!("OEM constraint does not match (0x{previous:x} != 0x{current:x})")
            }
            Self::SignatureVerificationFailed { source } => {
                format!("Signature verification failed: {source}")
            }
            Self::TokenKeyTypeMismatch => "Token signature algorithm does not match".to_string(),
            Self::TokenVerificationFailed { source } => {
                format!("Token signature verification failed: {source}")
            }
        }
    }
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CertificateValidationResult {
    pub index: usize,
    pub role: CertificateRole,
    pub errors: Vec<ValidationIssue>,
}

impl CertificateValidationResult {
    fn new(index: usize, role: CertificateRole) -> Self {
        Self {
            index,
            role,
            errors: Vec::new(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct EffectiveChainConstraints {
    pub usage: CertificateUsage,
    pub lifecycle: u16,
    pub oem_constraint: u16,
    pub soc_id: [u8; 16],
    pub soc_class: u32,
    pub policies: u16,
    pub permissions: [u8; 16],
}

impl Default for EffectiveChainConstraints {
    fn default() -> Self {
        Self {
            usage: CertificateUsage::AdacUsageNeutral,
            lifecycle: 0,
            oem_constraint: 0,
            soc_id: [0u8; 16],
            soc_class: 0,
            policies: 0,
            permissions: [0xffu8; 16],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainValidationResult {
    pub chain_errors: Vec<ValidationIssue>,
    pub certificates: Vec<CertificateValidationResult>,
    pub effective: EffectiveChainConstraints,
    pub leaf_terminated: bool,
}

impl ChainValidationResult {
    pub fn has_errors(&self) -> bool {
        !self.chain_errors.is_empty()
            || self
                .certificates
                .iter()
                .any(|certificate| !certificate.errors.is_empty())
    }

    pub fn first_error(&self) -> Option<&ValidationIssue> {
        self.chain_errors.first().or_else(|| {
            self.certificates
                .iter()
                .find_map(|certificate| certificate.errors.first())
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenValidationResult {
    pub errors: Vec<ValidationIssue>,
    pub effective_permissions: Option<[u8; 16]>,
}

impl TokenValidationResult {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

pub struct ChainValidator<'a> {
    policy: ChainValidationPolicy,
    crypto: &'a dyn AdacCryptoProvider,
    certificates: Vec<CertificateValidationResult>,
    effective: EffectiveChainConstraints,
    previous_public_key: Option<Vec<u8>>,
    terminal_key_type: Option<KeyOptions>,
}

impl<'a> ChainValidator<'a> {
    pub fn new(crypto: &'a dyn AdacCryptoProvider) -> Self {
        Self::with_policy(ChainValidationPolicy::default(), crypto)
    }

    pub fn with_policy(policy: ChainValidationPolicy, crypto: &'a dyn AdacCryptoProvider) -> Self {
        Self {
            policy,
            crypto,
            certificates: Vec::new(),
            effective: EffectiveChainConstraints::default(),
            previous_public_key: None,
            terminal_key_type: None,
        }
    }

    pub fn push_certificate(
        &mut self,
        certificate: &AdacCertificate,
    ) -> CertificateValidationResult {
        let index = self.certificates.len();
        let header = *certificate.header();
        let role = header.role;
        let key_type = header.key_type;
        let mut result = CertificateValidationResult::new(index, role);

        if index == 0 && role != CertificateRole::AdacCrtRoleRoot {
            result.errors.push(ValidationIssue::FirstCertificateNotRoot);
        }
        if index > 0 && role == CertificateRole::AdacCrtRoleRoot {
            result.errors.push(ValidationIssue::RootAfterFirst);
        }

        self.update_effective_constraints(&header, &mut result);

        let public_key = self
            .previous_public_key
            .as_deref()
            .unwrap_or_else(|| certificate.get_public_key());
        if let Err(e) = certificate.verify(public_key, self.crypto) {
            result
                .errors
                .push(ValidationIssue::SignatureVerificationFailed {
                    source: format!("{e:?}"),
                });
        }

        self.previous_public_key = Some(certificate.get_public_key().to_vec());
        self.terminal_key_type = Some(key_type);
        self.certificates.push(result.clone());
        result
    }

    pub fn validate_token(&self, token: &AdacToken, challenge: &[u8]) -> TokenValidationResult {
        let mut result = TokenValidationResult {
            errors: Vec::new(),
            effective_permissions: None,
        };

        let Some(public_key) = self.previous_public_key.as_deref() else {
            result.errors.push(ValidationIssue::EmptyChain);
            return result;
        };

        if self.terminal_key_type != Some(token.header().signature_type) {
            result.errors.push(ValidationIssue::TokenKeyTypeMismatch);
            return result;
        }

        if let Err(e) = token.verify(public_key, challenge, self.crypto) {
            result
                .errors
                .push(ValidationIssue::TokenVerificationFailed {
                    source: format!("{e:?}"),
                });
            return result;
        }

        let mut effective_permissions = self.effective.permissions;
        let requested_permissions = token.header().requested_permissions;
        for (i, permission) in effective_permissions.iter_mut().enumerate() {
            *permission &= requested_permissions[i];
        }
        result.effective_permissions = Some(effective_permissions);
        result
    }

    pub fn finish(mut self) -> ChainValidationResult {
        let mut chain_errors = Vec::new();
        if self.certificates.is_empty() {
            chain_errors.push(ValidationIssue::EmptyChain);
        }

        if self.certificates.len() > 1 {
            let last_index = self.certificates.len() - 1;
            for certificate in self.certificates.iter_mut().take(last_index) {
                if certificate.role == CertificateRole::AdacCrtRoleLeaf {
                    certificate.errors.push(ValidationIssue::LeafBeforeLast);
                }
            }
        }

        let leaf_terminated = self
            .certificates
            .last()
            .map(|certificate| certificate.role == CertificateRole::AdacCrtRoleLeaf)
            .unwrap_or(false);
        if self.policy.require_leaf_last
            && !leaf_terminated
            && let Some(last) = self.certificates.last_mut()
        {
            last.errors.push(ValidationIssue::MissingLeafLast);
        }

        ChainValidationResult {
            chain_errors,
            certificates: self.certificates,
            effective: self.effective,
            leaf_terminated,
        }
    }

    fn update_effective_constraints(
        &mut self,
        header: &adac::CertificateHeader,
        result: &mut CertificateValidationResult,
    ) {
        let usage = header.usage;
        let lifecycle = header.lifecycle;
        let oem_constraint = header.oem_constraint;
        let soc_id = header.soc_id;
        let soc_class = header.soc_class;
        let policies = header.policies;
        let permissions_mask = header.permissions_mask;

        if self.effective.usage == CertificateUsage::AdacUsageNeutral {
            self.effective.usage = usage;
        } else if self.effective.usage != usage {
            result.errors.push(ValidationIssue::UsageMismatch {
                previous: self.effective.usage,
                current: usage,
            });
        }

        if self.effective.soc_id == [0x0u8; 16] {
            self.effective.soc_id = soc_id;
        } else if self.effective.soc_id != soc_id {
            result.errors.push(ValidationIssue::SocIdMismatch {
                previous: self.effective.soc_id,
                current: soc_id,
            });
        }

        if self.effective.soc_class == 0 {
            self.effective.soc_class = soc_class;
        } else if soc_class != 0 && self.effective.soc_class != soc_class {
            result.errors.push(ValidationIssue::SocClassMismatch {
                previous: self.effective.soc_class,
                current: soc_class,
            });
        }

        if self.effective.lifecycle == 0 {
            self.effective.lifecycle = lifecycle;
        } else if lifecycle != 0 && self.effective.lifecycle != lifecycle {
            result.errors.push(ValidationIssue::LifecycleMismatch {
                previous: self.effective.lifecycle,
                current: lifecycle,
            });
        }

        if self.effective.oem_constraint == 0 {
            self.effective.oem_constraint = oem_constraint;
        } else if oem_constraint != 0 && self.effective.oem_constraint != oem_constraint {
            result.errors.push(ValidationIssue::OemConstraintMismatch {
                previous: self.effective.oem_constraint,
                current: oem_constraint,
            });
        }

        for (i, permission) in self.effective.permissions.iter_mut().enumerate() {
            *permission &= permissions_mask[i];
        }
        self.effective.policies |= policies;
    }
}

pub fn validate_chain(
    chain: &[AdacCertificate],
    crypto: &dyn AdacCryptoProvider,
) -> ChainValidationResult {
    validate_chain_with_policy(chain, ChainValidationPolicy::default(), crypto)
}

pub fn validate_chain_with_policy(
    chain: &[AdacCertificate],
    policy: ChainValidationPolicy,
    crypto: &dyn AdacCryptoProvider,
) -> ChainValidationResult {
    let mut validator = ChainValidator::with_policy(policy, crypto);
    for certificate in chain {
        validator.push_certificate(certificate);
    }
    validator.finish()
}

pub fn validate_token_signed_by_last_certificate(
    chain: &[AdacCertificate],
    token: &AdacToken,
    challenge: &[u8],
    crypto: &dyn AdacCryptoProvider,
) -> TokenValidationResult {
    let mut validator = ChainValidator::new(crypto);
    for certificate in chain {
        validator.push_certificate(certificate);
    }
    validator.validate_token(token, challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adac::{AdacError, CertificateHeader, traits::AdacKeyFormat};

    struct AcceptingProvider;

    impl AdacCryptoProvider for AcceptingProvider {
        fn verify(
            &self,
            _key_type: KeyOptions,
            _public_key: &[u8],
            _data: &[u8],
            _signature: &[u8],
        ) -> Result<(), AdacError> {
            Ok(())
        }

        fn hash(&self, key_type: KeyOptions, _data: &[u8]) -> Result<Vec<u8>, AdacError> {
            let (_, hash_size, _) = adac::certificate::adac_sizes_from_crypto(key_type)?;
            Ok(vec![0u8; hash_size])
        }

        fn sign(&mut self, key_type: KeyOptions, _data: &[u8]) -> Result<Vec<u8>, AdacError> {
            let (_, _, signature_size) = adac::certificate::adac_sizes_from_crypto(key_type)?;
            Ok(vec![0u8; signature_size])
        }

        fn load_key(
            &mut self,
            _key_type: KeyOptions,
            _format: AdacKeyFormat,
            _key: &[u8],
        ) -> Result<Vec<u8>, AdacError> {
            unimplemented!()
        }
    }

    fn certificate(role: CertificateRole) -> AdacCertificate {
        let key_type = KeyOptions::EcdsaP256Sha256;
        let (public_key_size, _, _) = adac::certificate::adac_sizes_from_crypto(key_type).unwrap();
        let header = CertificateHeader {
            role,
            ..CertificateHeader::default()
        };
        let public_key = vec![0u8; public_key_size];
        let mut provider = AcceptingProvider;
        AdacCertificate::sign(key_type, header, &public_key, None, &mut provider).unwrap()
    }

    #[test]
    fn validate_chain_reports_leaf_before_last() {
        let crypto = AcceptingProvider;
        let chain = vec![
            certificate(CertificateRole::AdacCrtRoleRoot),
            certificate(CertificateRole::AdacCrtRoleLeaf),
            certificate(CertificateRole::AdacCrtRoleInt),
        ];

        let result = validate_chain(&chain, &crypto);

        assert_eq!(
            result.certificates[1].errors[0],
            ValidationIssue::LeafBeforeLast
        );
    }

    #[test]
    fn validate_chain_reports_empty_chain() {
        let crypto = AcceptingProvider;

        let result = validate_chain(&[], &crypto);

        assert_eq!(result.chain_errors[0], ValidationIssue::EmptyChain);
    }
}
