// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::{
    AdacTlvHeader, KeyOptions, TokenHeader, certificate::AdacCertificate, token::AdacToken,
};

const CERTIFICATE_TLV_TYPE: u16 = 0x0201;

/// Encoding diagnostic with a decoded-byte offset and human-readable context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodingIssue {
    pub offset: usize,
    pub context: String,
    pub message: String,
}

impl EncodingIssue {
    fn new(offset: usize, context: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            offset,
            context: context.into(),
            message: message.into(),
        }
    }

    fn with_offset_and_context(self, offset: usize, context: &str) -> Self {
        let suffix = self
            .context
            .strip_prefix("certificate")
            .unwrap_or(&self.context);
        Self {
            offset: offset + self.offset,
            context: format!("{context}{suffix}"),
            message: self.message,
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct TlvSpan {
    value_offset: usize,
    value_len: usize,
    type_id: u16,
}

/// Validate decoded ADAC TLV sequence bytes.
///
/// Offsets are relative to `content`.
pub fn validate_tlvs(content: &[u8]) -> Vec<EncodingIssue> {
    let mut issues = Vec::<EncodingIssue>::new();
    validate_tlv_sequence(content, 0, "tlv-sequence", &mut issues);
    issues
}

/// Validate decoded ADAC certificate bytes.
///
/// Offsets are relative to `certificate`.
pub fn validate_certificate(certificate: &[u8]) -> Vec<EncodingIssue> {
    let mut issues = Vec::<EncodingIssue>::new();
    match AdacCertificate::from_bytes(certificate.to_vec()) {
        Ok(certificate) => {
            validate_certificate_extensions(&certificate, 0, "certificate", &mut issues)
        }
        Err(e) => issues.push(EncodingIssue::new(
            0,
            "certificate",
            format!("Invalid certificate encoding: {e:?}"),
        )),
    }
    issues
}

/// Validate decoded ADAC certificate-chain TLV sequence bytes.
///
/// Offsets are relative to `content`.
pub fn validate_certificate_chain(content: &[u8]) -> Vec<EncodingIssue> {
    let mut issues = Vec::<EncodingIssue>::new();
    let tlvs = validate_tlv_sequence(content, 0, "certificate-chain", &mut issues);
    for (i, tlv) in tlvs.iter().enumerate() {
        let context = format!("certificate-chain.tlv[{i}]");
        if tlv.type_id != CERTIFICATE_TLV_TYPE {
            issues.push(EncodingIssue::new(
                tlv.value_offset.saturating_sub(AdacTlvHeader::SIZE),
                context,
                format!("Invalid certificate TLV type 0x{:04x}", tlv.type_id),
            ));
            continue;
        }

        let value = &content[tlv.value_offset..tlv.value_offset + tlv.value_len];
        let context = format!("certificate-chain.tlv[{i}].certificate");
        issues.extend(
            validate_certificate(value)
                .into_iter()
                .map(|issue| issue.with_offset_and_context(tlv.value_offset, &context)),
        );
    }

    issues
}

/// Validate decoded ADAC token bytes.
///
/// Offsets are relative to `token`.
pub fn validate_token(token: &[u8]) -> Vec<EncodingIssue> {
    let mut issues = Vec::<EncodingIssue>::new();
    validate_token_structure(token, &mut issues);
    if let Ok(token) = AdacToken::from_bytes(token.to_vec()) {
        validate_token_extensions(&token, &mut issues);
    }

    issues
}

fn validate_tlv_sequence(
    mut bytes: &[u8],
    mut offset: usize,
    context: &str,
    issues: &mut Vec<EncodingIssue>,
) -> Vec<TlvSpan> {
    let mut spans = Vec::<TlvSpan>::new();
    let mut index = 0usize;

    while !bytes.is_empty() {
        let entry_context = format!("{context}.tlv[{index}]");
        if bytes.len() < AdacTlvHeader::SIZE {
            issues.push(EncodingIssue::new(
                offset,
                entry_context,
                "Remaining data too small for TLV header",
            ));
            break;
        }

        let reserved = bytes[1];
        let type_id = u16::from_le_bytes([bytes[2], bytes[3]]);
        let length = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let padding_len = tlv_padding_len(length);
        let Some(padded_len) = length.checked_add(padding_len) else {
            issues.push(EncodingIssue::new(
                offset + 4,
                entry_context,
                "TLV length overflows addressable size",
            ));
            break;
        };
        let Some(total_len) = AdacTlvHeader::SIZE.checked_add(padded_len) else {
            issues.push(EncodingIssue::new(
                offset + 4,
                entry_context,
                "TLV total length overflows addressable size",
            ));
            break;
        };

        if reserved != 0 {
            issues.push(EncodingIssue::new(
                offset + 1,
                entry_context.clone(),
                "Invalid nonzero TLV reserved field",
            ));
        }

        if total_len > bytes.len() {
            issues.push(EncodingIssue::new(
                offset + AdacTlvHeader::SIZE,
                entry_context,
                format!(
                    "TLV value length {} exceeds remaining {} bytes",
                    length,
                    bytes.len() - AdacTlvHeader::SIZE
                ),
            ));
            break;
        }

        let value_offset = offset + AdacTlvHeader::SIZE;
        let padding_start = AdacTlvHeader::SIZE + length;
        let padding_end = AdacTlvHeader::SIZE + padded_len;
        for (padding_index, byte) in bytes[padding_start..padding_end].iter().enumerate() {
            if *byte != 0 {
                issues.push(EncodingIssue::new(
                    value_offset + length + padding_index,
                    entry_context.clone(),
                    "Invalid nonzero TLV padding",
                ));
            }
        }

        spans.push(TlvSpan {
            value_offset,
            value_len: length,
            type_id,
        });

        bytes = &bytes[total_len..];
        offset += total_len;
        index += 1;
    }

    spans
}

fn validate_certificate_extensions(
    certificate: &AdacCertificate,
    certificate_offset: usize,
    context: &str,
    issues: &mut Vec<EncodingIssue>,
) {
    let header = *certificate.header();
    if header.extensions_bytes == 0 {
        return;
    }
    let extension_offset =
        certificate_offset + certificate.as_slice().len() - header.extensions_bytes as usize;
    validate_tlv_sequence(
        certificate.get_extensions(),
        extension_offset,
        context,
        issues,
    );
}

fn validate_token_structure(token: &[u8], issues: &mut Vec<EncodingIssue>) {
    if token.len() < TokenHeader::SIZE {
        issues.push(EncodingIssue::new(
            0,
            "token.header",
            format!(
                "Token is too short for header: {} < {} bytes",
                token.len(),
                TokenHeader::SIZE
            ),
        ));
        return;
    }

    if token[3] != 0 {
        issues.push(EncodingIssue::new(
            3,
            "token.header",
            "Invalid nonzero token reserved field",
        ));
    }

    let key_type = match KeyOptions::try_from(token[2]) {
        Ok(key_type) => key_type,
        Err(_) => {
            issues.push(EncodingIssue::new(
                2,
                "token.header",
                format!("Invalid token signature_type 0x{:02x}", token[2]),
            ));
            return;
        }
    };

    let extensions_bytes = u32::from_le_bytes([token[4], token[5], token[6], token[7]]) as usize;
    let Ok((hash_size, sig_size)) = adac::token::adac_sizes_from_crypto(key_type) else {
        issues.push(EncodingIssue::new(
            2,
            "token.header",
            format!("Unsupported token signature_type {key_type:?}"),
        ));
        return;
    };

    let expected_len = TokenHeader::SIZE
        .checked_add(hash_size)
        .and_then(|len| len.checked_add(sig_size))
        .and_then(|len| len.checked_add(extensions_bytes));
    match expected_len {
        Some(expected_len) if expected_len == token.len() => {}
        Some(expected_len) => issues.push(EncodingIssue::new(
            4,
            "token.header",
            format!(
                "Token length mismatch: header describes {expected_len} bytes, input has {} bytes",
                token.len()
            ),
        )),
        None => issues.push(EncodingIssue::new(
            4,
            "token.header",
            "Token length overflows addressable size",
        )),
    }
}

fn validate_token_extensions(token: &AdacToken, issues: &mut Vec<EncodingIssue>) {
    let header = *token.header();
    if header.extensions_bytes == 0 {
        return;
    }
    let extension_offset = token.as_slice().len() - header.extensions_bytes as usize;
    validate_tlv_sequence(
        token.get_extensions(),
        extension_offset,
        "token.extensions",
        issues,
    );
}

fn tlv_padding_len(length: usize) -> usize {
    (4 - (length % 4)) % 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_validator_reports_multiple_tlv_issues() {
        let mut bytes = adac::tlv_wrap(0x1234, vec![1]);
        let last = bytes.len() - 1;
        bytes[last] = 1;

        let issues = validate_certificate_chain(&bytes);

        assert!(
            issues
                .iter()
                .any(|issue| issue.message == "Invalid nonzero TLV padding")
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.message == "Invalid certificate TLV type 0x1234")
        );
    }

    #[test]
    fn tlv_validator_reports_only_tlv_issues() {
        let bytes = adac::tlv_wrap(0x1234, vec![1]);

        let issues = validate_tlvs(&bytes);

        assert!(issues.is_empty());
    }

    #[test]
    fn certificate_validator_reports_certificate_issue() {
        let issues = validate_certificate(&[1, 2, 3]);

        assert!(
            issues
                .iter()
                .any(|issue| issue.message == "Invalid certificate encoding: InvalidLength")
        );
    }

    #[test]
    fn token_validator_reports_short_header() {
        let issues = validate_token(&[1, 2, 3]);

        assert!(issues.iter().any(|issue| issue.context == "token.header"));
    }
}
