// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub fn make_temp_dir(prefix: &str) -> PathBuf {
    let test_name = std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "{prefix}-{test_name}-{}-{suffix}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}
