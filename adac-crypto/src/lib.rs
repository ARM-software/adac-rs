// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod encoding;
pub mod public;
pub mod utils;
pub mod validation;

pub const ML_DSA_44_OID: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
pub const ML_DSA_65_OID: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
pub const ML_DSA_87_OID: pkcs8::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");
pub const ED_448_OID: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("1.3.101.113");
pub const RSA_OID: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub const SM2_OID: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("1.2.156.10197.1.301");
