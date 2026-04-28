// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput, config, shared};
use adac::CertificateHeader;
use adac::certificate::AdacCertificate;
use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
use adac_crypto::utils::{load_certificates, load_key, load_public_key, save_certificates};
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::ops::DerefMut;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct CertficateSignatureReport {
    pub certificate: String,
    pub path: Option<PathBuf>,
}

impl CertficateSignatureReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        if self.path.is_none() {
            writeln!(out, "{}", self.certificate)?;
        }
        Ok(())
    }
}

pub fn certificate_sign_command(
    config: &PathBuf,
    issuer: &Option<PathBuf>,
    output: &Option<PathBuf>,
    private_key: &Option<PathBuf>,
    module: &Option<String>,
    slot: &Option<String>,
    pin: &Option<shared::PinSecret>,
    pin_file: &Option<String>,
    pin_env: &Option<String>,
    key_id: &Option<String>,
    public_key: &PathBuf,
    section: &Option<String>,
) -> anyhow::Result<CommandOutput, CommandError> {
    let config = fs::read_to_string(config).map_err(|e| CommandError::FileRead {
        path: config.clone(),
        source: e,
    })?;
    let config = config::parse_adac_configuration(&config, (*section).clone()).map_err(|e| {
        CommandError::AdacError {
            source: anyhow::anyhow!("Error parsing configuration file: {:?}", e),
        }
    })?;
    let public_key = load_public_key(public_key).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error loading public key: {:?}", e),
    })?;

    let mut crypto: Box<dyn AdacCryptoProvider> = if let Some(key_id) = key_id {
        let key_id = shared::decode_base16_parameter(key_id, "--key-id")?;
        let kt = public_key.get_key_type();

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

        let pin = shared::resolve_pkcs11_pin(pin, pin_file, pin_env)?;

        let mut crypto = shared::create_pkcs11_provider(module, pin, slot)?;
        crypto
            .load_key(kt, AdacKeyFormat::KeyId, key_id.as_slice())
            .map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error loading PKCS#11 key: {:?}", e),
            })?;
        Box::new(crypto)
    } else {
        let mut crypto = adac_crypto_rust::RustCryptoProvider::default();
        let private_key = private_key.clone();
        let private_key = if let Some(path) = private_key {
            path.clone()
        } else {
            return Err(CommandError::AdacError {
                source: anyhow::anyhow!("Parameter --private-key or --key-id required."),
            });
        };

        let (kt, private_key) = load_key(private_key).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error loading key file: {:?}", e),
        })?;
        crypto
            .load_key(kt, AdacKeyFormat::Pkcs8, private_key.clone().as_slice())
            .map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error parsing PKCS#8 key: {:?}", e),
            })?;
        if public_key.get_key_type() != kt {
            return Err(CommandError::AdacError {
                source: anyhow::anyhow!("Key types in private/public key do not match."),
            });
        }
        Box::new(crypto)
    };

    let kt = public_key.get_key_type();
    let h = CertificateHeader {
        format_version: config.format_version,
        key_type: kt,
        signature_type: kt,
        role: config.role,
        usage: config.usage,
        lifecycle: config.lifecycle,
        oem_constraint: config.oem_constraint,
        soc_class: config.soc_class,
        soc_id: config.soc_id,
        permissions_mask: config.permissions_mask,
        ..Default::default()
    };

    let extensions = if !config.extensions.is_empty() {
        Some(config.extensions.as_slice())
    } else {
        None
    };

    let certificate =
        AdacCertificate::sign(kt, h, public_key.get_adac(), extensions, crypto.deref_mut())
            .map_err(|e| CommandError::AdacError {
                source: anyhow::anyhow!("Error signing certificate: {:?}", e),
            })?;

    let chain = if let Some(path) = issuer {
        let mut c = load_certificates(path).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
        })?;
        shared::verify_certificate_signed_by_issuer(c.as_slice(), &certificate)?;
        c.push(certificate);
        c
    } else {
        vec![certificate]
    };

    let certificate = save_certificates(&chain).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error serializing certificates: {:?}", e),
    })?;

    if let Some(path) = output {
        let mut file = fs::File::create(path).map_err(|e| CommandError::FileWrite {
            path: path.clone(),
            source: e,
        })?;
        file.write_all(certificate.as_bytes())
            .map_err(|e| CommandError::FileWrite {
                path: path.clone(),
                source: e,
            })?;
    }
    let path = output.clone();
    Ok(CommandOutput::CertificateSign(CertficateSignatureReport {
        certificate,
        path,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests;

    #[test]
    fn certificate_sign_command_rejects_certificate_not_signed_by_issuer() {
        let dir = tests::make_temp_dir("adac-cli-sign-tests");
        let config_path = tests::write_cert_config(&dir);
        let root_public =
            tests::write_public_key_from_private(&dir, "EcdsaP384Key-0.pk8", "root.pub");
        let leaf_public =
            tests::write_public_key_from_private(&dir, "EcdsaP384Key-2.pk8", "leaf.pub");
        let root_path = dir.join("root.crt");

        certificate_sign_command(
            &config_path,
            &None,
            &Some(root_path.clone()),
            &Some(tests::fixture_path("keys", "EcdsaP384Key-0.pk8")),
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &root_public,
            &Some("root".to_string()),
        )
        .unwrap();

        let err = certificate_sign_command(
            &config_path,
            &Some(root_path),
            &None,
            &Some(tests::fixture_path("keys", "EcdsaP384Key-1.pk8")),
            &None,
            &None,
            &None,
            &None,
            &None,
            &None,
            &leaf_public,
            &Some("intermediate".to_string()),
        )
        .unwrap_err();

        match err {
            CommandError::AdacError { source } => {
                assert!(
                    source
                        .to_string()
                        .contains("does not verify against issuer chain")
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let _ = fs::remove_dir_all(dir);
    }
}
