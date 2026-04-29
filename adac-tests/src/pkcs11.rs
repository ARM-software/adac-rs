// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::KeyOptions::*;
use adac::traits::{AdacCryptoProvider, AdacKeyFormat};
use adac::{AdacError, KeyOptions};
use adac_crypto::utils::{read_certificates, read_key};
use adac_cryptoki::private::{generate_keypair, import_key, sign};
use adac_cryptoki::public::{import_public_key, verify};
use console::Emoji;
use cryptoki::mechanism::MechanismType;
use cryptoki::object::ObjectHandle;
use cryptoki::session::Session;
use cryptoki_sys::CK_MECHANISM_TYPE;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::ops::Deref;
use std::thread;
use std::time::Duration;

static CONSTRUCTION: Emoji<'_, '_> = Emoji("🚧", "");
static CROSS_MARK: Emoji<'_, '_> = Emoji("❌", "");
static CROSS_MARK_BUTTON: Emoji<'_, '_> = Emoji("❎", "");
static DOWN_ARROW: Emoji<'_, '_> = Emoji("⬇️️", "");
static FLOPPY_DISK: Emoji<'_, '_> = Emoji("💾", "");
static GEAR: Emoji<'_, '_> = Emoji("⚙️", "");
static KEY: Emoji<'_, '_> = Emoji("🔑", "");
static LOCKED: Emoji<'_, '_> = Emoji("🔒", "");
static LOCKED_WITH_KEY: Emoji<'_, '_> = Emoji("🔐", "");
static LOCKED_WITH_PEN: Emoji<'_, '_> = Emoji("🔏", "");
static MAGNIFYING_GLASS: Emoji<'_, '_> = Emoji("🔎", "");
static WASTEBASKET: Emoji<'_, '_> = Emoji("🗑️", "");
static UNLOCKED: Emoji<'_, '_> = Emoji("🔓", "");
static WHITE_HEAVY_CHECK_MARK: Emoji<'_, '_> = Emoji("✅️", "");
static WARNING: Emoji<'_, '_> = Emoji("⚠️", "");

pub fn adac_check(module: String, pin: String, label: Option<String>) {
    let (pkcs11, slot, _session) =
        adac_cryptoki::pkcs11_create_session(module, pin, label).unwrap();

    if let Ok(mechanisms) = pkcs11.get_mechanism_list(slot) {
        println!("\n┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓");
        let checks = vec![
            (
                "ECDSA",
                CK_MECHANISM_TYPE::from(MechanismType::ECDSA),
                vec![
                    ("EcdsaP256Sha256", 256),
                    ("EcdsaP384Sha384", 384),
                    ("EcdsaP521Sha512", 521),
                ],
            ),
            (
                "RSA-PSS",
                CK_MECHANISM_TYPE::from(MechanismType::RSA_PKCS_PSS),
                vec![("Rsa3072Sha256", 3072), ("Rsa4096Sha256", 4096)],
            ),
            (
                "EDDSA",
                CK_MECHANISM_TYPE::from(MechanismType::EDDSA),
                vec![("Ed25519Sha512", 256), ("Ed448Shake256", 448)],
            ),
            ("ML-DSA", CK_MECHANISM_TYPE::from(0x0000001Du64), vec![]),
        ];
        let mut first = true;
        for c in checks {
            if first {
                first = false;
            } else {
                println!("┣━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━┫")
            }
            if mechanisms.iter().any(|x| *x.deref() == c.1) {
                println!("┃ {:<7}  ┃ ✅ Supported        ┃", c.0);
                let m = if let Ok(m) = MechanismType::try_from(c.1) {
                    m
                } else {
                    continue;
                };
                if let Ok(mi) = pkcs11.get_mechanism_info(slot, m) {
                    let s = if mi.sign() { "✅" } else { "❌" };
                    let v = if mi.verify() { "✅" } else { "❌" };
                    println!("┃          ┃ Sign: {} Verify: {} ┃", s, v);
                    for a in c.2 {
                        let m = if mi.max_key_size() >= a.1 - 1 && mi.min_key_size() <= a.1 + 1 {
                            "✅"
                        } else {
                            "❌"
                        };
                        println!("┃          ┃ {:>15}: {} ┃", a.0, m);
                    }
                }
            } else {
                println!("┃ {:<7}  ┃ ❌ Not supported    ┃", c.0);
            }
        }
        println!("┗━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━┛\n");
    }
}

fn display_result(progress: &(ProgressBar, bool, Option<AdacError>), step: &(Emoji, &str)) {
    thread::sleep(Duration::from_millis(10));
    let mark = if progress.1 {
        WHITE_HEAVY_CHECK_MARK
    } else {
        CROSS_MARK
    };
    let msg = format!("{} {}: {}", step.0, mark, step.1);
    progress.0.set_message(msg);
    progress.0.inc(1);
    thread::sleep(Duration::from_millis(10));
}

fn display_final(
    multi: MultiProgress,
    progress: Vec<(ProgressBar, bool, Option<AdacError>)>,
    steps: Vec<(Emoji, &str)>,
) {
    for p in &progress {
        p.0.finish_and_clear()
    }
    multi.clear().unwrap();

    for (i, step) in steps.iter().enumerate() {
        if progress[i].1 {
            println!("- {} {} {}", WHITE_HEAVY_CHECK_MARK, step.0, step.1);
        } else if let Some(e) = &progress[i].2 {
            let e = if let AdacError::CryptoProviderError(msg) = e {
                msg
            } else {
                &format!("{:?}", e)
            };
            println!("- {} {} {}: {}", CROSS_MARK, step.0, step.1, e);
        } else {
            println!("- {} {} {}", CROSS_MARK, step.0, step.1);
        }
    }
}

#[derive(Copy, Clone)]
struct TestCase {
    key_type: KeyOptions,
    name: &'static str,
    import_key: Option<&'static str>,
    certificate: &'static str,
}

static TESTS: [TestCase; 10] = [
    TestCase {
        key_type: EcdsaP256Sha256,
        name: "EcdsaP256Sha256",
        import_key: Some(include_str!("../resources/keys/EcdsaP256Key-0.pk8")),
        certificate: include_str!("../resources/roots/root.EcdsaP256"),
    },
    TestCase {
        key_type: EcdsaP384Sha384,
        name: "EcdsaP384Sha384",
        import_key: Some(include_str!("../resources/keys/EcdsaP384Key-0.pk8")),
        certificate: include_str!("../resources/roots/root.EcdsaP384"),
    },
    TestCase {
        key_type: EcdsaP521Sha512,
        name: "EcdsaP521Sha512",
        import_key: Some(include_str!("../resources/keys/EcdsaP521Key-0.pk8")),
        certificate: include_str!("../resources/roots/root.EcdsaP521"),
    },
    TestCase {
        key_type: Rsa3072Sha256,
        name: "Rsa3072Sha256",
        import_key: Some(include_str!("../resources/keys/Rsa3072Key-0.pk8")),
        certificate: include_str!("../resources/roots/root.Rsa3072"),
    },
    TestCase {
        key_type: Rsa4096Sha256,
        name: "Rsa4096Sha256",
        import_key: Some(include_str!("../resources/keys/Rsa4096Key-0.pk8")),
        certificate: include_str!("../resources/roots/root.Rsa4096"),
    },
    TestCase {
        key_type: Ed25519Sha512,
        name: "Ed25519Sha512",
        import_key: Some(include_str!("../resources/keys/Ed25519Key-0.pk8")),
        certificate: include_str!("../resources/roots/root.Ed25519"),
    },
    TestCase {
        key_type: Ed448Shake256,
        name: "Ed448Shake256",
        import_key: Some(include_str!("../resources/keys/Ed448Key-0.pk8")),
        certificate: include_str!("../resources/roots/root.Ed448"),
    },
    TestCase {
        key_type: MlDsa44Sha256,
        name: "MlDsa44Sha256",
        import_key: None,
        certificate: include_str!("../resources/roots/root.MlDsa44"),
    },
    TestCase {
        key_type: MlDsa65Sha384,
        name: "MlDsa65Sha384",
        import_key: None,
        certificate: include_str!("../resources/roots/root.MlDsa65"),
    },
    TestCase {
        key_type: MlDsa87Sha512,
        name: "MlDsa87Sha512",
        import_key: None,
        certificate: include_str!("../resources/roots/root.MlDsa87"),
    },
];

pub fn adac_test(module: String, pin: String, label: Option<String>) {
    let (_pkcs11, _slot, session) =
        adac_cryptoki::pkcs11_create_session(module, pin, label).unwrap();
    let spinner_style = ProgressStyle::with_template("{bar} {wide_msg}").unwrap();

    for t in TESTS {
        println!("\n{}", t.name);
        let mut steps = vec![
            (KEY, "Key generation"),
            (LOCKED_WITH_KEY, "Sign"),
            (UNLOCKED, "Verify"),
            (WASTEBASKET, "Delete keypair"),
        ];
        if t.import_key.is_some() {
            steps.extend([
                (FLOPPY_DISK, "Load keypair"),
                (DOWN_ARROW, "Import keypair"),
                (LOCKED_WITH_KEY, "Sign"),
                (UNLOCKED, "Verify"),
                (WASTEBASKET, "Delete keypair"),
            ]);
        }
        steps.push((MAGNIFYING_GLASS, "Verify certificate"));
        let mut progress: Vec<(ProgressBar, bool, Option<AdacError>)> = vec![];
        let multi = MultiProgress::new();
        for step in &steps {
            let pb = multi.add(ProgressBar::new(1));
            pb.set_style(spinner_style.clone());
            pb.set_message(format!("{}:    {}", step.0, step.1));
            progress.push((pb, false, None));
        }
        let mut step = 0;

        // ---------------------------------------------------------------------------------------
        let (_kid, _key_id, _ski, private, public) = match generate_keypair(&session, t.key_type) {
            Ok(keys) => {
                progress[step].1 = true;
                keys
            }
            Err(e) => {
                progress[step].2 = Some(e);
                display_final(multi, progress, steps);
                continue;
            }
        };
        display_result(&progress[step], &steps[step]);
        step += 1;

        test_signature(
            &session,
            t.key_type,
            &steps[step..=(step + 1)],
            &mut progress[step..=(step + 1)],
            private,
            public,
        );
        step += 2;

        delete_keypair(
            &session,
            &steps[step..(step + 1)],
            &mut progress[step..(step + 1)],
            private,
            public,
        );
        step += 1;

        // ---------------------------------------------------------------------------------------
        if let Some(import_key_path) = t.import_key {
            let (kt, key) = read_key(import_key_path.to_string()).unwrap();
            if kt == t.key_type {
                progress[step].1 = true;
            } else {
                display_final(multi, progress, steps);
                continue;
            }
            display_result(&progress[step], &steps[step]);
            step += 1;

            let (_, _, _, private, public) = match import_key(&session, t.key_type, key) {
                Ok(key) => {
                    progress[step].1 = true;
                    key
                }
                Err(e) => {
                    progress[step].2 = Some(e);
                    display_final(multi, progress, steps);
                    continue;
                }
            };

            display_result(&progress[step], &steps[step]);
            step += 1;

            test_signature(
                &session,
                t.key_type,
                &steps[step..=(step + 1)],
                &mut progress[step..=(step + 1)],
                private,
                public,
            );
            step += 2;

            delete_keypair(
                &session,
                &steps[step..(step + 1)],
                &mut progress[step..(step + 1)],
                private,
                public,
            );
            step += 1;
        }

        // ---------------------------------------------------------------------------------------
        let crt = read_certificates(t.certificate.to_string()).unwrap();
        let crypto = TestCryptoProvider { session: &session };
        match crt[0].verify(crt[0].get_public_key(), &crypto) {
            Ok(()) => {
                progress[step].1 = true;
            }
            Err(_) => {
                let msg = "It is likely that the phFlag in CKK_EDDSA_PARAMS is ignored".to_string();
                if t.key_type == Ed25519Sha512 || t.key_type == Ed448Shake256 {
                    progress[step].2 = Some(AdacError::CryptoProviderError(msg));
                };
            }
        }
        display_result(&progress[step], &steps[step]);

        display_final(multi, progress, steps);
    }
}

struct TestCryptoProvider<'a> {
    session: &'a Session,
}

impl<'a> AdacCryptoProvider for TestCryptoProvider<'a> {
    fn verify(
        &self,
        key_type: KeyOptions,
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), AdacError> {
        let handle = import_public_key(self.session, key_type, public_key)?;
        verify(self.session, key_type, handle, data, signature)
    }

    fn hash(&self, key_type: KeyOptions, data: &[u8]) -> Result<Vec<u8>, AdacError> {
        adac_cryptoki::hash(self.session, key_type, data)
    }

    fn sign(&mut self, _key_type: KeyOptions, _data: &[u8]) -> Result<Vec<u8>, AdacError> {
        Err(AdacError::UnsupportedAlgorithm)
    }

    fn load_key(
        &mut self,
        _key_type: KeyOptions,
        _format: AdacKeyFormat,
        _key: &[u8],
    ) -> Result<Vec<u8>, AdacError> {
        Err(AdacError::UnsupportedAlgorithm)
    }
}

fn test_signature(
    session: &Session,
    key_type: KeyOptions,
    steps: &[(Emoji, &str)],
    progress: &mut [(ProgressBar, bool, Option<AdacError>)],
    private: ObjectHandle,
    public: ObjectHandle,
) {
    let msg = [0u8; 128];

    match sign(session, key_type, private, msg.as_slice()) {
        Ok(signature) => {
            progress[0].1 = true;
            display_result(&progress[0], &steps[0]);

            match verify(session, key_type, public, msg.as_slice(), &signature) {
                Ok(()) => {
                    progress[1].1 = true;
                }
                Err(e) => {
                    progress[1].2 = Some(e);
                }
            }
        }
        Err(e) => {
            progress[0].2 = Some(e);
            display_result(&progress[0], &steps[0]);
        }
    }
    display_result(&progress[1], &steps[1])
}

fn delete_keypair(
    session: &Session,
    steps: &[(Emoji, &str)],
    progress: &mut [(ProgressBar, bool, Option<AdacError>)],
    private: ObjectHandle,
    public: ObjectHandle,
) {
    let a = session.destroy_object(private);
    let b = session.destroy_object(public);
    if a.is_ok() && b.is_ok() {
        progress[0].1 = true;
    } else {
        if let Err(e) = a {
            let e = AdacError::CryptoProviderError(format!("Error deleting private key: {}", e));
            progress[0].2 = Some(e);
        }
        if let Err(e) = b {
            let e = AdacError::CryptoProviderError(format!("Error deleting private key: {}", e));
            progress[0].2 = Some(e);
        }
    }
    display_result(&progress[0], &steps[0]);
}
