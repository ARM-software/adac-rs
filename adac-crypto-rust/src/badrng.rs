// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use rand::{CryptoRng, RngCore};

pub(crate) struct BadRng {}

impl CryptoRng for BadRng {}

impl RngCore for BadRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest.iter_mut() {
            *d = 0;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        for d in dest.iter_mut() {
            *d = 0;
        }
        Ok(())
    }
}
