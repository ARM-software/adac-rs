// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::{CommandError, CommandOutput, config};
use adac::certificate::{AdacCertificate, adac_sizes_from_crypto};
use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
use adac::{CertificateHeader, KeyOptions};
use adac_crypto::utils::{load_certificates, load_public_key, save_certificates};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct PrepareReport {
    pub certificate: String,
    pub tbs: String,
    pub hash: String,
    pub crt_path: Option<PathBuf>,
    pub tbs_path: Option<PathBuf>,
    pub hash_path: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct MergeReport {
    pub certificate: String,
    pub path: Option<PathBuf>,
}

impl PrepareReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        if self.crt_path.is_none() {
            writeln!(out, "{}", self.certificate)?;
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

impl MergeReport {
    pub fn text_output(&self, out: &mut dyn Write) -> anyhow::Result<()> {
        if self.path.is_none() {
            writeln!(out, "{}", self.certificate)?;
        }
        Ok(())
    }
}

pub struct PrepareCryptoProvider {
    key_type: KeyOptions,
    hash: Vec<u8>,
    tbs: Vec<u8>,
}

impl PrepareCryptoProvider {
    pub fn new(key_type: KeyOptions, hash: Vec<u8>, tbs: Vec<u8>) -> Self {
        PrepareCryptoProvider {
            key_type,
            hash,
            tbs,
        }
    }
}

impl AdacCryptoProvider for PrepareCryptoProvider {
    fn verify(
        &self,
        key_type: adac::KeyOptions,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), adac::AdacError> {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();
        crypto.verify(key_type, public_key, data, signature)
    }

    fn hash(&self, key_type: adac::KeyOptions, data: &[u8]) -> Result<Vec<u8>, adac::AdacError> {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();
        crypto.hash(key_type, data)
    }

    fn sign(
        &mut self,
        key_type: adac::KeyOptions,
        data: &[u8],
    ) -> Result<Vec<u8>, adac::AdacError> {
        let (_, _, sig_size) = adac_sizes_from_crypto(key_type)?;
        let mut v = Vec::<u8>::with_capacity(sig_size);
        v.extend(std::iter::repeat_n(0, sig_size));
        self.tbs = data.to_vec();
        self.hash = self.hash(key_type, data)?;
        if self.key_type != key_type {
            // TODO
        }
        Ok(v)
    }

    fn load_key(
        &mut self,
        key_type: adac::KeyOptions,
        format: AdacKeyFormat,
        key: &[u8],
    ) -> Result<Vec<u8>, adac::AdacError> {
        let mut crypto = adac_crypto_rust::RustCryptoProvider::default();
        crypto.load_key(key_type, format, key)
    }
}

pub fn prepare_command(
    config: &PathBuf,
    request: &PathBuf,
    section: &Option<String>,
    crt_path: &Option<PathBuf>,
    tbs_path: &Option<PathBuf>,
    hash_path: &Option<PathBuf>,
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
    let public_key = load_public_key(request).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error loading public key: {:?}", e),
    })?;

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

    let mut crypto = PrepareCryptoProvider::new(kt, vec![], vec![]);
    let certificate = AdacCertificate::sign(kt, h, public_key.get_adac(), extensions, &mut crypto)
        .map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error signing certificate: {:?}", e),
        })?;

    let tbs = crypto.tbs;
    let hash = crypto.hash;

    let chain = vec![certificate];
    let certificate = save_certificates(&chain).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error serializing certificates: {:?}", e),
    })?;

    if let Some(path) = crt_path {
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

    if let Some(path) = tbs_path {
        let mut file = fs::File::create(path).map_err(|e| CommandError::FileWrite {
            path: path.clone(),
            source: e,
        })?;
        file.write_all(&tbs).map_err(|e| CommandError::FileWrite {
            path: path.clone(),
            source: e,
        })?;
    }

    if let Some(path) = hash_path {
        let mut file = fs::File::create(path).map_err(|e| CommandError::FileWrite {
            path: path.clone(),
            source: e,
        })?;
        file.write_all(&hash).map_err(|e| CommandError::FileWrite {
            path: path.clone(),
            source: e,
        })?;
    }

    let hash = base16ct::lower::encode_string(hash.as_slice());
    let tbs = BASE64_STANDARD.encode(tbs.as_slice());

    let crt_path = crt_path.clone();
    let tbs_path = tbs_path.clone();
    let hash_path = hash_path.clone();
    Ok(CommandOutput::SignOfflinePrepare(PrepareReport {
        certificate,
        tbs,
        hash,
        crt_path,
        tbs_path,
        hash_path,
    }))
}

pub struct MergeCryptoProvider {
    key_type: KeyOptions,
    signature: Vec<u8>,
}

impl AdacCryptoProvider for MergeCryptoProvider {
    fn verify(
        &self,
        key_type: adac::KeyOptions,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), adac::AdacError> {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();
        crypto.verify(key_type, public_key, data, signature)
    }

    fn hash(&self, key_type: adac::KeyOptions, data: &[u8]) -> Result<Vec<u8>, adac::AdacError> {
        let crypto = adac_crypto_rust::RustCryptoProvider::default();
        crypto.hash(key_type, data)
    }

    fn sign(
        &mut self,
        key_type: adac::KeyOptions,
        _data: &[u8],
    ) -> Result<Vec<u8>, adac::AdacError> {
        if self.key_type != key_type {
            // TODO
        }
        let (_, _, sig_size) = adac_sizes_from_crypto(key_type)?;
        if self.signature.len() != sig_size {
            // TODO: Check
        }
        Ok(self.signature.clone())
    }

    fn load_key(
        &mut self,
        key_type: adac::KeyOptions,
        format: AdacKeyFormat,
        key: &[u8],
    ) -> Result<Vec<u8>, adac::AdacError> {
        let mut crypto = adac_crypto_rust::RustCryptoProvider::default();
        crypto.load_key(key_type, format, key)
    }
}

impl MergeCryptoProvider {
    pub fn new(key_type: KeyOptions, signature: Vec<u8>) -> Self {
        MergeCryptoProvider {
            key_type,
            signature,
        }
    }
}

pub fn merge_command(
    issuer: &Option<PathBuf>,
    output: &Option<PathBuf>,
    input: &PathBuf,
    signature: &PathBuf,
) -> anyhow::Result<CommandOutput, CommandError> {
    let template = load_certificates(input).map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
    })?;

    let certificate = if let Some(c) = template.first() {
        c
    } else {
        return Err(CommandError::AdacError {
            source: anyhow::anyhow!("Certificate file is empty"),
        });
    };

    let sig = fs::read(signature).map_err(|e| CommandError::FileRead {
        path: signature.clone(),
        source: e,
    })?;

    let sig = adac_crypto::utils::convert_signature(certificate.header().key_type, sig.as_slice())
        .map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error parsing signature: {:?}", e),
        })?;

    let mut crypto = MergeCryptoProvider::new(certificate.header().key_type, sig);
    let extensions = if !certificate.get_extensions().is_empty() {
        Some(certificate.get_extensions())
    } else {
        None
    };
    let certificate = AdacCertificate::sign(
        certificate.header().key_type,
        *certificate.header(),
        certificate.get_public_key(),
        extensions,
        &mut crypto,
    )
    .map_err(|e| CommandError::AdacError {
        source: anyhow::anyhow!("Error signing certificate: {:?}", e),
    })?;

    let chain = if let Some(path) = issuer {
        let mut c = load_certificates(path).map_err(|e| CommandError::AdacError {
            source: anyhow::anyhow!("Error loading certificate chain: {:?}", e),
        })?;
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
    Ok(CommandOutput::SignOfflineMerge(MergeReport {
        certificate,
        path,
    }))
}
