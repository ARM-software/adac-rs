// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod config;
pub mod display;
pub mod misc;
pub mod offline;
pub mod pkcs11;
pub mod shared;
pub mod sign;
pub mod token;
pub mod verify;

use serde::Serialize;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutput {
    Display(display::DisplayReport),
    Pkcs11Generate(pkcs11::Pkcs11GenerateReport),
    Pop(misc::PopReport),
    Push(misc::PushReport),
    RotHash(misc::RotReport),
    CertificateSign(sign::CertficateSignatureReport),
    CertificateOfflinePrepare(offline::PrepareReport),
    CertificateOfflineMerge(offline::MergeReport),
    TokenSign(token::TokenSignatureReport),
    TokenOfflinePrepare(token::TokenPrepareReport),
    TokenOfflineMerge(token::TokenMergeReport),
    Verify(verify::VerificationReport),
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("Failed to read file from {path}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Failed to write to {path}")]
    FileWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Invalid value for parameter {parameter}")]
    InvalidParameter { parameter: String },
    #[error("ADAC Library Error")]
    AdacError {
        #[source]
        source: anyhow::Error,
    },
}
