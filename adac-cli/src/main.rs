// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

mod config;
mod display;
mod misc;
mod offline;
mod pkcs11;
mod sign;
mod verify;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::{fs::OpenOptions, io, sync::OnceLock};
use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, filter::LevelFilter, fmt, fmt::writer::BoxMakeWriter};

use display::DisplayReport;
use misc::{PopReport, PushReport, RotReport};
use offline::{MergeReport, PrepareReport, merge_command, prepare_command};
use pkcs11::Pkcs11GenerateReport;
use sign::SignatureReport;
use verify::VerificationReport;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Serialize)]
struct JsonError {
    error: String,
    sources: Vec<String>,
}

/// ADAC Certificate CLI Tool.
#[derive(Parser, Debug)]
#[command(name = "adac-cli", version)]
struct Cli {
    /// Increase log verbosity (-v, -vv, ...).
    #[arg(short = 'v', long, action = ArgAction::Count, global = true)]
    verbose: u8,
    /// Set minimum log level (error, warn, info, debug, trace).
    #[arg(long, value_enum, default_value_t = LogLevel::Warn, global = true)]
    log_level: LogLevel,
    /// Choose log format (text or json).
    #[arg(long, value_enum, default_value_t = LogFormat::Text, global = true)]
    log_format: LogFormat,
    /// Choose command output format (text or json).
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, global = true)]
    output_format: OutputFormat,
    /// Append logs to the given file instead of stderr.
    #[arg(long, global = true, value_name = "PATH")]
    log_file: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Commands,
}

impl Cli {
    fn effective_level(&self) -> LevelFilter {
        self.log_level.bump(self.verbose)
    }
}

impl LogLevel {
    fn bump(self, verbose: u8) -> LevelFilter {
        match self.index() + verbose {
            0 => LevelFilter::ERROR,
            1 => LevelFilter::WARN,
            2 => LevelFilter::INFO,
            3 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        }
    }

    fn index(self) -> u8 {
        match self {
            LogLevel::Error => 0,
            LogLevel::Warn => 1,
            LogLevel::Info => 2,
            LogLevel::Debug => 3,
            LogLevel::Trace => 4,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Display certificate (chain) content.
    #[command(version, about, long_about = None)]
    Display {
        /// Path to the certificate or certificate chain to display.
        #[arg(short, long, value_name = "PATH")]
        path: PathBuf,
        /// Show only the leaf certificate.
        #[arg(short, long)]
        leaf: bool,
        /// Include the PEM-encoded certificate(s) in the command output.
        #[arg(long)]
        print: bool,
    },
    /// Generate keys using a PKCS#11 provider.
    #[command(name = "pkcs11-keygen")]
    Pkcs11 {
        /// Key type to generate (e.g. EcdsaP384Sha384, Rsa4096Sha256).
        #[arg(short, long, value_name = "TYPE")]
        key_type: String,
        /// Path to the PKCS#11 provider library. Defaults to $PKCS11_MODULE.
        #[arg(short, long, value_name = "LIBRARY")]
        module: Option<String>,
        /// Slot label identifying the token. Defaults to $PKCS11_SLOT.
        #[arg(short, long, value_name = "LABEL")]
        label: Option<String>,
        /// User PIN for the slot. Defaults to --pin-file/--pin-env or $PKCS11_PIN.
        #[arg(long, value_name = "PIN")]
        pin: Option<String>,
        /// Read the user PIN from the specified file.
        #[arg(long, value_name = "FILE")]
        pin_file: Option<String>,
        /// Read the user PIN from the named environment variable (defaults to PKCS11_PIN).
        #[arg(long, value_name = "ENV")]
        pin_env: Option<String>,
    },
    /// Extract the last certificate in a chain.
    Pop {
        /// Path to the certificate or certificate chain.
        #[arg(short, long, value_name = "PATH")]
        path: PathBuf,
        /// Write the extracted certificate to this file instead of stdout.
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
    },
    /// Add certificate(s) to a chain.
    Push {
        /// Path to the certificate or certificate chain.
        #[arg(value_name = "CHAIN")]
        chain: PathBuf,
        /// Path to the additional certificate or certificate chain.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Write the resulting certificate chain to this file instead of stdout.
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
    },
    /// Extract Root of Trust public-key hash.
    #[command(name = "rot-hash")]
    RotHash {
        /// Path to the certificate or certificate chain.
        #[arg(short, long, value_name = "PATH")]
        path: PathBuf,
        /// Hash algorithm: sha256 (default), sha384 or sha512
        #[arg(long, value_name = "ALGO", value_parser = ["sha256", "sha384", "sha512"])]
        hash: Option<String>,
    },
    /// Sign a certificate.
    Sign {
        /// Signing configuration file (TOML).
        #[arg(short, long, value_name = "CONFIG")]
        config: PathBuf,
        /// Existing issuer certificate chain to append to (required for non-root certs).
        #[arg(short, long, value_name = "CHAIN")]
        issuer: Option<PathBuf>,
        /// Write the resulting certificate chain to this file.
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
        /// Issuer private key in PKCS#8 format (required unless --key-id is used).
        #[arg(short, long, value_name = "KEY")]
        private: Option<PathBuf>,
        /// PKCS#11 provider library to load when using --key-id.
        #[arg(short, long, value_name = "LIBRARY")]
        module: Option<String>,
        /// Slot label identifying the PKCS#11 token. Defaults to $PKCS11_SLOT.
        #[arg(long, value_name = "LABEL")]
        label: Option<String>,
        /// User PIN for the PKCS#11 slot. Defaults to --pin-file/--pin-env or $PKCS11_PIN.
        #[arg(long, value_name = "PIN")]
        pin: Option<String>,
        /// Read the PKCS#11 user PIN from this file.
        #[arg(long, value_name = "FILE")]
        pin_file: Option<String>,
        /// Read the PKCS#11 user PIN from the named environment variable (defaults to PKCS11_PIN).
        #[arg(long, value_name = "ENV")]
        pin_env: Option<String>,
        /// PKCS#11 key identifier to use for signing.
        #[arg(short, long, value_name = "KEYID")]
        key_id: Option<String>,
        /// Public key to incorporate into the certificate.
        #[arg(short, long, value_name = "PUBLIC_KEY")]
        request: PathBuf,
        /// Configuration file section to apply (defaults to [defaults]).
        #[arg(short, long, value_name = "SECTION")]
        section: Option<String>,
    },
    /// Prepare an offline certificate signature.
    #[command(name = "sign-offline-prepare", alias = "offline-prepare")]
    SignOfflinePrepare {
        /// Signing configuration file (TOML).
        #[arg(short, long, value_name = "CONFIG")]
        config: PathBuf,
        /// Public key to incorporate into the certificate.
        #[arg(short, long, value_name = "PUBLIC_KEY")]
        request: PathBuf,
        /// Configuration file section to apply (defaults to [defaults]).
        #[arg(short, long, value_name = "SECTION")]
        section: Option<String>,
        /// Write the (pre-)certificate chain to this file.
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
        /// Write the to-be-signed payload (TBS) to this file.
        #[arg(short, long, value_name = "FILE")]
        tbs: Option<PathBuf>,
        /// Write the hash of the TBS payload to this file.
        #[arg(long, value_name = "FILE")]
        hash: Option<PathBuf>,
    },
    /// Merge an offline signature.
    #[command(name = "sign-offline-merge", alias = "offline-merge")]
    SignOfflineMerge {
        /// Issuer certificate chain to prepend the signed certificate to.
        #[arg(short, long, value_name = "CHAIN")]
        issuer: Option<PathBuf>,
        /// Write the resulting certificate chain to this file.
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
        /// (Pre-)Certificate produced by offline-prepare.
        #[arg(short, long, value_name = "IN")]
        request: PathBuf,
        /// Detached signature to merge into the certificate.
        #[arg(short, long, value_name = "SIG")]
        signature: PathBuf,
    },
    /// Verify certificate (chain) content.
    Verify {
        /// Path to the certificate or certificate chain to verify.
        #[arg(short, long, value_name = "PATH")]
        path: PathBuf,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum CommandOutput {
    Display(DisplayReport),
    Pkcs11Generate(Pkcs11GenerateReport),
    Pop(PopReport),
    Push(PushReport),
    RotHash(RotReport),
    Sign(SignatureReport),
    SignOfflinePrepare(PrepareReport),
    SignOfflineMerge(MergeReport),
    Verify(VerificationReport),
}

#[derive(Debug, Error)]
enum CommandError {
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

static LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

fn main() {
    let cli = Cli::parse();

    match wrapped_main(&cli) {
        Ok(r) => std::process::exit(r),
        Err(error) => {
            tracing::error!(error = ?error, "command failed");
            if let Err(report_err) = display_error(&error, cli.output_format) {
                eprintln!("error: {report_err}");
            }
            std::process::exit(1);
        }
    }
}

fn display_error(error: &anyhow::Error, format: OutputFormat) -> io::Result<()> {
    match format {
        OutputFormat::Text => {
            let mut stderr = io::stderr().lock();
            writeln!(stderr, "error: {}", error)?;
        }
        OutputFormat::Json => {
            let payload = JsonError {
                error: error.to_string(),
                sources: error.chain().skip(1).map(ToString::to_string).collect(),
            };
            let mut stderr = io::stderr().lock();
            serde_json::to_writer(&mut stderr, &payload).map_err(io::Error::other)?;
            stderr.write_all(b"\n")?;
        }
    }
    Ok(())
}

fn wrapped_main(cli: &Cli) -> Result<i32> {
    let make_writer = if let Some(path) = &cli.log_file {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("unable to open log file at {path:?}"))?;
        let (writer, guard) = tracing_appender::non_blocking(file);

        let _ = LOG_GUARD.set(guard);
        BoxMakeWriter::new(writer)
    } else {
        BoxMakeWriter::new(std::io::stderr)
    };

    let builder = fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(cli.effective_level().into())
                .from_env_lossy(),
        )
        .with_target(false)
        .with_writer(make_writer)
        .with_ansi(cli.log_file.is_none() && cli.log_format == LogFormat::Text);

    match cli.log_format {
        LogFormat::Text => builder
            .try_init()
            .map_err(|error| anyhow::anyhow!("failed to install text subscriber: {error}"))?,
        LogFormat::Json => builder
            .json()
            .try_init()
            .map_err(|error| anyhow::anyhow!("failed to install json subscriber: {error}"))?,
    }

    let output = match &cli.cmd {
        Commands::Display { path, leaf, print } => {
            display::display_command(path, leaf, print, cli.verbose)
        }
        Commands::Pkcs11 {
            key_type,
            module,
            pin,
            pin_file,
            pin_env,
            label,
        } => pkcs11::pkcs11_generate_command(key_type, module, label, pin, pin_file, pin_env),
        Commands::Pop { path, output } => misc::pop_command(path, output),
        Commands::Push {
            chain,
            path,
            output,
        } => misc::push_command(chain, path, output),
        Commands::RotHash { path, hash } => misc::rot_command(path, hash),
        Commands::Sign {
            config,
            issuer,
            output,
            private,
            module,
            label,
            pin,
            pin_file,
            pin_env,
            key_id,
            request,
            section,
        } => sign::sign_command(
            config, issuer, output, private, module, label, pin, pin_file, pin_env, key_id, request,
            section,
        ),
        Commands::SignOfflinePrepare {
            config,
            request,
            section,
            output,
            tbs,
            hash,
        } => prepare_command(config, request, section, output, tbs, hash),
        Commands::SignOfflineMerge {
            issuer,
            output,
            request,
            signature,
        } => merge_command(issuer, output, request, signature),
        Commands::Verify { path } => verify::verify_command(path),
    }
    .with_context(|| format!("{:?} command failed", cli.cmd))?;

    match cli.output_format {
        OutputFormat::Text => {
            let mut stdout = io::stdout().lock();
            match &output {
                CommandOutput::Display(d) => {
                    d.text_output(&mut stdout)?;
                }
                CommandOutput::Pkcs11Generate(p) => {
                    p.text_output(&mut stdout)?;
                }
                CommandOutput::Pop(p) => {
                    p.text_output(&mut stdout)?;
                }
                CommandOutput::Push(p) => {
                    p.text_output(&mut stdout)?;
                }
                CommandOutput::RotHash(r) => {
                    r.text_output(&mut stdout)?;
                }
                CommandOutput::Sign(s) => {
                    s.text_output(&mut stdout)?;
                }
                CommandOutput::SignOfflinePrepare(p) => {
                    p.text_output(&mut stdout)?;
                }
                CommandOutput::SignOfflineMerge(m) => {
                    m.text_output(&mut stdout)?;
                }
                CommandOutput::Verify(v) => {
                    v.text_output(&mut stdout)?;
                }
            }
        }
        OutputFormat::Json => {
            let mut stdout = io::stdout().lock();
            serde_json::to_writer(&mut stdout, &output)
                .context("failed to serialize JSON output")?;
            stdout.write_all(b"\n")?;
        }
    }

    if let CommandOutput::Verify(out) = &output {
        return Ok(out.error_code());
    }

    Ok(0)
}
