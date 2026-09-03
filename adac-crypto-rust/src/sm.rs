// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use digest::Digest;

pub fn sm3_digest(msg: &[u8]) -> Vec<u8> {
    let mut hasher = sm3::Sm3::new();
    sm3::Digest::update(&mut hasher, msg);
    hasher.finalize().to_vec()
}
