// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput};
use adac_crypto::utils::{load_certificates, save_certificates};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct DisplayReport {
    certificates: Vec<DisplayCertificate>,
    pem: Option<String>,
    verbose: u8,
}

impl DisplayReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        for (i, crt) in self.certificates.iter().enumerate() {
            if i > 0 {
                writeln!(out, "--------------------")?;
            }
            if self.certificates.len() > 1 {
                writeln!(out, "Certificate {} of {}", i + 1, self.certificates.len())?;
            } else {
                writeln!(out, "Certificate")?;
            }
            writeln!(out, "  Version: {}", crt.version)?;
            writeln!(out, "  Key type: {}", crt.key_type)?;
            writeln!(out, "  Signature type: {}", crt.signature_type)?;
            writeln!(out, "  Role: {}", crt.role)?;
            writeln!(out, "  Usage: {}", crt.usage)?;
            if let Some(p) = &crt.policies {
                writeln!(out, "  Policies: {}", p)?;
            }
            writeln!(out, "  Lifecycle: {}", crt.lifecycle)?;
            writeln!(out, "  Custom constraint: {}", crt.oem_constraint)?;
            writeln!(out, "  SoC Class: {}", crt.soc_class)?;

            writeln!(out, "  SoC ID: {} ({})", crt.soc_id_be, crt.soc_id_raw)?;

            writeln!(
                out,
                "  Permission Mask: {} ({})",
                crt.permissions_mask_be, crt.permissions_mask_raw
            )?;

            writeln!(out, "Public key: {}", crt.public_key)?;

            if let Some(ext) = &crt.extensions {
                writeln!(out, "Extensions ({} bytes)", ext.bytes)?;
                writeln!(out, "  Hash: {}", ext.hash)?;
                writeln!(out, "  Value: {}", ext.value)?;
            }
            if self.verbose > 0 {
                writeln!(out, "Signature: {}", crt.signature)?;
            }
        }

        if let Some(crt) = &self.pem {
            writeln!(out)?;
            writeln!(out, "{}", crt)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct DisplayCertificate {
    version: String,
    key_type: String,
    signature_type: String,
    role: String,
    usage: String,
    policies: Option<String>,
    lifecycle: String,
    oem_constraint: String,
    soc_class: String,
    soc_id_be: String,
    soc_id_raw: String,
    permissions_mask_be: String,
    permissions_mask_raw: String,
    public_key: String,
    extensions: Option<DisplayExtension>,
    signature: String,
}

#[derive(Debug, Serialize)]
pub struct DisplayExtension {
    bytes: u32,
    hash: String,
    value: String,
}

pub fn display_command(
    path: &PathBuf,
    leaf: &bool,
    print: &bool,
    verbose: u8,
) -> anyhow::Result<CommandOutput, CommandError> {
    let mut chain = load_certificates(path).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
    })?;
    if *leaf && let Some(crt) = chain.pop() {
        chain = vec![crt];
    }

    let mut certificates = Vec::new();

    for crt in &chain {
        let header = crt.header();
        let version = format!(
            "{}.{}",
            header.format_version.major, header.format_version.minor
        );
        let key_type = format!("{:?}", header.key_type);
        let signature_type = format!("{:?}", header.signature_type);
        let role = format!("{:?}", header.role);
        let usage = format!("{:?}", header.usage);
        let policies = if (header.format_version.major > 1) || (header.format_version.minor > 0) {
            let policies = header.policies;
            Some(format!(" 0x{:x}", policies))
        } else {
            None
        };
        let lifecycle = header.lifecycle;
        let lifecycle = format!(" 0x{:x}", lifecycle);
        let oem_constraint = header.oem_constraint;
        let oem_constraint = format!(" 0x{:x}", oem_constraint);
        let soc_class = header.soc_class;
        let soc_class = format!(" 0x{:x}", soc_class);

        let mut soc_id = [0x0u8; 16];
        soc_id.copy_from_slice(u128::from_le_bytes(header.soc_id).to_be_bytes().as_ref());
        let soc_id_be = format!("0x{}", base16ct::lower::encode_string(soc_id.as_slice()));
        let soc_id_raw = base16ct::lower::encode_string(header.soc_id.as_slice());

        let mut permissions_mask = [0x00u8; 16];
        permissions_mask.copy_from_slice(
            u128::from_le_bytes(header.permissions_mask)
                .to_be_bytes()
                .as_ref(),
        );
        let permissions_mask_be = format!(
            "0x{}",
            base16ct::lower::encode_string(permissions_mask.as_slice())
        );
        let permissions_mask_raw =
            base16ct::lower::encode_string(header.permissions_mask.as_slice());

        let public_key = base16ct::lower::encode_string(crt.get_public_key());

        let extensions = if header.extensions_bytes > 0 {
            Some(DisplayExtension {
                bytes: header.extensions_bytes,
                hash: base16ct::lower::encode_string(crt.get_extensions_hash()),
                value: base16ct::lower::encode_string(crt.get_extensions()),
            })
        } else {
            None
        };

        let signature = base16ct::lower::encode_string(crt.get_signature());

        certificates.push(DisplayCertificate {
            version,
            key_type,
            signature_type,
            role,
            usage,
            policies,
            lifecycle,
            oem_constraint,
            soc_class,
            soc_id_be,
            soc_id_raw,
            permissions_mask_be,
            permissions_mask_raw,
            public_key,
            extensions,
            signature,
        })
    }

    let pem = if *print {
        Some(
            save_certificates(&chain).map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error serializing certificates: {:?}", e),
            })?,
        )
    } else {
        None
    };

    Ok(CommandOutput::Display(DisplayReport {
        certificates,
        pem,
        verbose,
    }))
}
