// Copyright (c) 2019-2025, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::{AdacError, AdacVersion, CertificateRole, CertificateUsage};
use toml::{Table, Value};

#[derive(Debug, PartialEq)]
pub struct AdacCertificateConfig {
    pub format_version: AdacVersion,
    pub role: CertificateRole,
    pub usage: CertificateUsage,
    pub policies: u16,
    pub lifecycle: u16,
    pub oem_constraint: u16,
    pub soc_class: u32,
    pub soc_id: [u8; 16],
    pub permissions_mask: [u8; 16],
    pub extensions: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct AdacTokenConfig {
    pub format_version: AdacVersion,
    pub requested_permissions: [u8; 16],
    pub extensions: Vec<u8>,
}

pub fn parse_adac_configuration(
    config: &str,
    section: Option<String>,
) -> Result<AdacCertificateConfig, AdacError> {
    let cfg = config
        .parse::<Table>()
        .map_err(|e| AdacError::Encoding(format!("Error parsing configuration: {}", e)))?;

    let defaults = cfg
        .get("defaults")
        .ok_or(AdacError::Encoding("Missing defaults section".to_string()))?;
    if !defaults.is_table() {
        return Err(AdacError::Encoding(
            "Key 'defaults' is not a section".to_string(),
        ));
    }
    let version_major = defaults
        .get("version_major")
        .ok_or(AdacError::Encoding(
            "Missing default 'version_major' value".to_string(),
        ))?
        .as_integer()
        .ok_or(AdacError::Encoding(
            "Value for default 'version_major' is not integer".to_string(),
        ))?;
    let version_minor = defaults
        .get("version_minor")
        .ok_or(AdacError::Encoding(
            "Missing default 'version_minor' value".to_string(),
        ))?
        .as_integer()
        .ok_or(AdacError::Encoding(
            "Value for default 'version_minor' is not integer".to_string(),
        ))?;
    if version_major != 1 || !(0..=1).contains(&version_minor) {
        return Err(AdacError::Encoding(
            "Invalid values for version".to_string(),
        ));
    }
    let (major, minor) = (version_major as u8, version_minor as u8);
    let format_version = AdacVersion { major, minor };

    let role = defaults
        .get("role")
        .ok_or(AdacError::Encoding(
            "Missing default 'role' value".to_string(),
        ))?
        .as_integer()
        .ok_or(AdacError::Encoding(
            "Value for default 'role' is not integer".to_string(),
        ))?;
    let role = if (0..256).contains(&role) {
        CertificateRole::try_from(role as u8).map_err(|_| {
            AdacError::Encoding(format!("Value for default 'role' {} is invalid", role))
        })?
    } else {
        return Err(AdacError::Encoding(format!(
            "Value for default 'role' {} is invalid",
            role
        )));
    };

    let usage = defaults
        .get("usage")
        .ok_or(AdacError::Encoding(
            "Missing default 'usage' value".to_string(),
        ))?
        .as_integer()
        .ok_or(AdacError::Encoding(
            "Value for default 'usage' is not integer".to_string(),
        ))?;
    let usage = if (0..256).contains(&usage) {
        CertificateUsage::try_from(usage as u8).map_err(|_| {
            AdacError::Encoding(format!("Value for default 'usage' {} is invalid", usage))
        })?
    } else {
        return Err(AdacError::Encoding(format!(
            "Value for default 'usage' {} is invalid",
            usage
        )));
    };

    let policies = defaults
        .get("policies")
        .unwrap_or(&Value::Integer(0))
        .as_integer()
        .ok_or(AdacError::Encoding(
            "Value for default 'policies' is not integer".to_string(),
        ))?;
    let policies = if policies <= u16::MAX as i64 && policies >= 0 {
        policies as u16
    } else {
        return Err(AdacError::Encoding(format!(
            "Value for default 'policies' {} is invalid",
            policies
        )));
    };

    let lifecycle = defaults
        .get("lifecycle")
        .ok_or(AdacError::Encoding(
            "Missing default 'lifecycle' value".to_string(),
        ))?
        .as_integer()
        .ok_or(AdacError::Encoding(
            "Value for default 'lifecycle' is not integer".to_string(),
        ))?;
    let lifecycle = if lifecycle <= u16::MAX as i64 && lifecycle >= 0 {
        lifecycle as u16
    } else {
        return Err(AdacError::Encoding(format!(
            "Value for default 'lifecycle' {} is invalid",
            lifecycle
        )));
    };

    let oem_constraint = defaults
        .get("oem_constraint")
        .ok_or(AdacError::Encoding(
            "Missing default 'oem_constraint' value".to_string(),
        ))?
        .as_integer()
        .ok_or(AdacError::Encoding(
            "Value for default 'oem_constraint' is not integer".to_string(),
        ))?;
    let oem_constraint = if oem_constraint <= u16::MAX as i64 && oem_constraint >= 0 {
        oem_constraint as u16
    } else {
        return Err(AdacError::Encoding(format!(
            "Value for default 'oem_constraint' {} is invalid",
            oem_constraint
        )));
    };

    let soc_class = defaults
        .get("soc_class")
        .ok_or(AdacError::Encoding(
            "Missing default 'soc_class' value".to_string(),
        ))?
        .as_integer()
        .ok_or(AdacError::Encoding(
            "Value for default 'soc_class' is not integer".to_string(),
        ))?;
    let soc_class = if soc_class <= u32::MAX as i64 && soc_class >= 0 {
        soc_class as u32
    } else {
        return Err(AdacError::Encoding(format!(
            "Value for default 'soc_class' {} is invalid",
            soc_class
        )));
    };

    let id = defaults
        .get("soc_id")
        .ok_or(AdacError::Encoding(
            "Missing default 'soc_id' value".to_string(),
        ))?
        .as_str()
        .ok_or(AdacError::Encoding(
            "Value for default 'soc_id' is not String".to_string(),
        ))?;

    let id = if let Some(hex) = id.strip_prefix("0x") {
        hex::decode(hex).map_err(|_| {
            AdacError::Encoding("Value for 'soc_id' is not properly hex encoded".to_string())
        })?
    } else {
        return Err(AdacError::Encoding(
            "Value for 'soc_id' does not start with '0x'".to_string(),
        ));
    };
    if id.len() != 16 {
        return Err(AdacError::Encoding(
            "Length for 'soc_id' is invalid".to_string(),
        ));
    }
    let mut soc_id: [u8; 16] = [0u8; 16];
    let id = u128::from_be_bytes(id.as_slice().try_into().unwrap());
    soc_id.copy_from_slice(id.to_le_bytes().as_ref());

    let permissions = defaults
        .get("permissions_mask")
        .ok_or(AdacError::Encoding(
            "Missing default 'permissions_mask' value".to_string(),
        ))?
        .as_str()
        .ok_or(AdacError::Encoding(
            "Value for default 'permissions_mask' is not String".to_string(),
        ))?;

    let permissions = if let Some(hex) = permissions.strip_prefix("0x") {
        hex::decode(hex).map_err(|_| {
            AdacError::Encoding(
                "Value for default 'permissions_mask' is not properly hex encoded".to_string(),
            )
        })?
    } else {
        return Err(AdacError::Encoding(
            "Value for 'permissions_mask' does not start with '0x'".to_string(),
        ));
    };
    if permissions.len() != 16 {
        return Err(AdacError::Encoding(
            "Length for default 'permissions_mask' is invalid".to_string(),
        ));
    }

    let permissions = u128::from_be_bytes(permissions.as_slice().try_into().unwrap());
    let mut permissions_mask: [u8; 16] = [0u8; 16];
    permissions_mask.copy_from_slice(permissions.to_le_bytes().as_ref());

    let extensions = defaults
        .get("extensions")
        .ok_or(AdacError::Encoding(
            "Missing default 'extensions' value".to_string(),
        ))?
        .as_str()
        .ok_or(AdacError::Encoding(
            "Value for default 'extensions' is not String".to_string(),
        ))?;
    let extensions = if !extensions.is_empty() {
        hex::decode(extensions).map_err(|_| {
            AdacError::Encoding(
                "Value for default 'extensions' is not properly hex encoded".to_string(),
            )
        })?
    } else {
        vec![]
    };

    let mut c = AdacCertificateConfig {
        format_version,
        role,
        usage,
        policies,
        lifecycle,
        oem_constraint,
        soc_class,
        soc_id,
        permissions_mask,
        extensions,
    };

    let section = match section {
        Some(s) => s,
        None => return Ok(c),
    };

    let sec = cfg
        .get(section.as_str())
        .ok_or(AdacError::Encoding(format!(
            "Unknown section '{}'",
            section
        )))?;
    if !sec.is_table() {
        return Err(AdacError::Encoding(format!(
            "Key '{}' is not section",
            section
        )));
    }
    if let Some(version_major) = sec.get("version_major") {
        let major = version_major.as_integer().ok_or(AdacError::Encoding(
            "Value for 'version_major' is not integer".to_string(),
        ))?;
        if !(0..=1).contains(&major) {
            return Err(AdacError::Encoding(
                "Invalid values for version_major".to_string(),
            ));
        }
        c.format_version.major = major as u8;
    }
    if let Some(version_minor) = sec.get("version_minor") {
        let minor = version_minor.as_integer().ok_or(AdacError::Encoding(
            "Value for 'version_minor' is not integer".to_string(),
        ))?;
        if !(0..=1).contains(&minor) {
            return Err(AdacError::Encoding(
                "Invalid values for version_minor".to_string(),
            ));
        }
        c.format_version.minor = minor as u8;
    }

    if let Some(role) = sec.get("role") {
        let role = role.as_integer().ok_or(AdacError::Encoding(
            "Value for 'role' is not integer".to_string(),
        ))?;
        c.role = if !(0..=255).contains(&role) {
            return Err(AdacError::Encoding(format!(
                "Value for 'role' {} is invalid",
                role
            )));
        } else {
            CertificateRole::try_from(role as u8)
                .map_err(|_| AdacError::Encoding(format!("Value for 'role' {} is invalid", role)))?
        };
    }

    if let Some(usage) = sec.get("usage") {
        let usage = usage.as_integer().ok_or(AdacError::Encoding(
            "Value for 'usage' is not integer".to_string(),
        ))?;
        c.usage = if !(0..=255).contains(&usage) {
            return Err(AdacError::Encoding(format!(
                "Value for 'usage' {} is invalid",
                usage
            )));
        } else {
            CertificateUsage::try_from(usage as u8).map_err(|_| {
                AdacError::Encoding(format!("Value for 'usage' {} is invalid", usage))
            })?
        };
    }

    if let Some(policies) = sec.get("policies") {
        let policies = policies.as_integer().unwrap_or(0);

        c.policies = if (policies > u16::MAX as i64) || policies < 0 {
            return Err(AdacError::Encoding(format!(
                "Value for 'policies' {} is invalid",
                policies
            )));
        } else {
            policies as u16
        };
    }

    if let Some(lifecycle) = sec.get("lifecycle") {
        let lifecycle = lifecycle.as_integer().ok_or(AdacError::Encoding(
            "Value for 'lifecycle' is not integer".to_string(),
        ))?;
        c.lifecycle = if (lifecycle > u16::MAX as i64) || lifecycle < 0 {
            return Err(AdacError::Encoding(format!(
                "Value for 'lifecycle' {} is invalid",
                lifecycle
            )));
        } else {
            lifecycle as u16
        };
    }

    if let Some(oem_constraint) = sec.get("oem_constraint") {
        let oem_constraint = oem_constraint.as_integer().ok_or(AdacError::Encoding(
            "Value for 'oem_constraint' is not integer".to_string(),
        ))?;
        c.oem_constraint = if (oem_constraint > u16::MAX as i64) || oem_constraint < 0 {
            return Err(AdacError::Encoding(format!(
                "Value for 'oem_constraint' {} is invalid",
                oem_constraint
            )));
        } else {
            oem_constraint as u16
        };
    }

    if let Some(soc_class) = sec.get("soc_class") {
        let soc_class = soc_class.as_integer().ok_or(AdacError::Encoding(
            "Value for 'soc_class' is not integer".to_string(),
        ))?;
        c.soc_class = if (soc_class > u32::MAX as i64) || soc_class < 0 {
            return Err(AdacError::Encoding(format!(
                "Value for 'soc_class' {} is invalid",
                soc_class
            )));
        } else {
            soc_class as u32
        };
    }

    if let Some(soc_id) = sec.get("soc_id") {
        let soc_id = soc_id.as_str().ok_or(AdacError::Encoding(
            "Value for 'soc_id' is not String".to_string(),
        ))?;
        let soc_id = if let Some(hex) = soc_id.strip_prefix("0x") {
            hex::decode(hex).map_err(|_| {
                AdacError::Encoding("Value for 'soc_id' is not properly hex encoded".to_string())
            })?
        } else {
            return Err(AdacError::Encoding(
                "Value for 'soc_id' does not start with '0x'".to_string(),
            ));
        };
        if soc_id.len() != 16 {
            return Err(AdacError::Encoding(
                "Length for 'soc_id' is invalid".to_string(),
            ));
        }
        let soc_id = u128::from_be_bytes(soc_id.as_slice().try_into().unwrap());
        c.soc_id.copy_from_slice(soc_id.to_le_bytes().as_ref());
    }

    if let Some(permissions_mask) = sec.get("permissions_mask") {
        let permissions_mask = permissions_mask.as_str().ok_or(AdacError::Encoding(
            "Value for 'permissions_mask' is not String".to_string(),
        ))?;
        let permissions_mask = if let Some(hex) = permissions_mask.strip_prefix("0x") {
            hex::decode(hex).map_err(|_| {
                AdacError::Encoding(
                    "Value for 'permissions_mask' is not properly hex encoded".to_string(),
                )
            })?
        } else {
            return Err(AdacError::Encoding(
                "Value for 'permissions_mask' does not start with '0x'".to_string(),
            ));
        };
        if permissions_mask.len() != 16 {
            return Err(AdacError::Encoding(
                "Length for 'permissions_mask' is invalid".to_string(),
            ));
        }
        let permissions_mask = u128::from_be_bytes(permissions_mask.as_slice().try_into().unwrap());
        c.permissions_mask
            .copy_from_slice(permissions_mask.to_le_bytes().as_ref());
    }

    if let Some(extensions) = sec.get("extensions") {
        let extensions = extensions.as_str().ok_or(AdacError::Encoding(
            "Value for 'extensions' is not String".to_string(),
        ))?;
        c.extensions = if !extensions.is_empty() {
            if let Some(hex) = extensions.strip_prefix("0x") {
                hex::decode(hex).map_err(|_| {
                    AdacError::Encoding(
                        "Value for 'extensions' is not properly hex encoded".to_string(),
                    )
                })?
            } else {
                return Err(AdacError::Encoding(
                    "Value for 'extensions' does not start with '0x'".to_string(),
                ));
            }
        } else {
            vec![]
        };
    }

    Ok(c)
}

pub fn parse_adac_token_configuration(
    config: &str,
    section: Option<String>,
) -> Result<AdacTokenConfig, AdacError> {
    let cfg = config
        .parse::<Table>()
        .map_err(|e| AdacError::Encoding(format!("Error parsing configuration: {}", e)))?;

    let defaults = cfg
        .get("defaults")
        .ok_or(AdacError::Encoding("Missing defaults section".to_string()))?;
    if !defaults.is_table() {
        return Err(AdacError::Encoding(
            "Key 'defaults' is not a section".to_string(),
        ));
    }

    let version_major = defaults
        .get("version_major")
        .ok_or(AdacError::Encoding(
            "Missing default 'version_major' value".to_string(),
        ))?
        .as_integer()
        .ok_or(AdacError::Encoding(
            "Value for default 'version_major' is not integer".to_string(),
        ))?;
    let version_minor = defaults
        .get("version_minor")
        .ok_or(AdacError::Encoding(
            "Missing default 'version_minor' value".to_string(),
        ))?
        .as_integer()
        .ok_or(AdacError::Encoding(
            "Value for default 'version_minor' is not integer".to_string(),
        ))?;
    if version_major != 1 || !(0..=1).contains(&version_minor) {
        return Err(AdacError::Encoding(
            "Invalid values for version".to_string(),
        ));
    }

    let requested_permissions = defaults
        .get("requested_permissions")
        .ok_or(AdacError::Encoding(
            "Missing default 'requested_permissions' value".to_string(),
        ))?
        .as_str()
        .ok_or(AdacError::Encoding(
            "Value for default 'requested_permissions' is not String".to_string(),
        ))?;
    let requested_permissions =
        parse_permissions_field(requested_permissions, "default 'requested_permissions'")?;

    let extensions = parse_optional_extensions(defaults, "default 'extensions'")?;

    let mut c = AdacTokenConfig {
        format_version: AdacVersion {
            major: version_major as u8,
            minor: version_minor as u8,
        },
        requested_permissions,
        extensions,
    };

    let section = match section {
        Some(s) => s,
        None => return Ok(c),
    };

    let sec = cfg
        .get(section.as_str())
        .ok_or(AdacError::Encoding(format!(
            "Unknown section '{}'",
            section
        )))?;
    if !sec.is_table() {
        return Err(AdacError::Encoding(format!(
            "Key '{}' is not section",
            section
        )));
    }

    if let Some(version_major) = sec.get("version_major") {
        let major = version_major.as_integer().ok_or(AdacError::Encoding(
            "Value for 'version_major' is not integer".to_string(),
        ))?;
        if !(0..=1).contains(&major) {
            return Err(AdacError::Encoding(
                "Invalid values for version_major".to_string(),
            ));
        }
        c.format_version.major = major as u8;
    }
    if let Some(version_minor) = sec.get("version_minor") {
        let minor = version_minor.as_integer().ok_or(AdacError::Encoding(
            "Value for 'version_minor' is not integer".to_string(),
        ))?;
        if !(0..=1).contains(&minor) {
            return Err(AdacError::Encoding(
                "Invalid values for version_minor".to_string(),
            ));
        }
        c.format_version.minor = minor as u8;
    }
    if c.format_version.major != 1 || c.format_version.minor > 1 {
        return Err(AdacError::Encoding(
            "Invalid values for version".to_string(),
        ));
    }

    if let Some(requested_permissions) = sec.get("requested_permissions") {
        let requested_permissions = requested_permissions.as_str().ok_or(AdacError::Encoding(
            "Value for 'requested_permissions' is not String".to_string(),
        ))?;
        c.requested_permissions =
            parse_permissions_field(requested_permissions, "'requested_permissions'")?;
    }

    if sec.get("extensions").is_some() {
        c.extensions = parse_optional_extensions(sec, "'extensions'")?;
    }

    Ok(c)
}

fn parse_permissions_field(value: &str, field: &str) -> Result<[u8; 16], AdacError> {
    let permissions = if let Some(hex) = value.strip_prefix("0x") {
        hex::decode(hex).map_err(|_| {
            AdacError::Encoding(format!("Value for {} is not properly hex encoded", field))
        })?
    } else {
        return Err(AdacError::Encoding(format!(
            "Value for {} does not start with '0x'",
            field
        )));
    };
    if permissions.len() != 16 {
        return Err(AdacError::Encoding(format!(
            "Length for {} is invalid",
            field
        )));
    }

    let permissions = u128::from_be_bytes(permissions.as_slice().try_into().unwrap());
    Ok(permissions.to_le_bytes())
}

fn parse_optional_extensions(table: &Value, field: &str) -> Result<Vec<u8>, AdacError> {
    let Some(extensions) = table.get("extensions") else {
        return Ok(vec![]);
    };
    let extensions = extensions.as_str().ok_or(AdacError::Encoding(format!(
        "Value for {} is not String",
        field
    )))?;
    if extensions.is_empty() {
        return Ok(vec![]);
    }

    let Some(hex) = extensions.strip_prefix("0x") else {
        return Err(AdacError::Encoding(format!(
            "Value for {} does not start with '0x'",
            field
        )));
    };

    hex::decode(hex).map_err(|_| {
        AdacError::Encoding(format!("Value for {} is not properly hex encoded", field))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 0
role = 3
usage = 0
lifecycle = 0
oem_constraint = 0
soc_class = 0
soc_id = "0x00000000000000000000000000000000"
permissions_mask = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = ""

[root]
role = 1

[intermediate]
role = 2
usage = 1

[extensions]
soc_id = "0x00112233445566778899AABB00000000"
permissions_mask = "0x00000000FFFFFFFFFFFFFFFFFFFFFFFF"
extensions = "0x0102030405060708090a0b0c0d0e0f"
"#;
        let c = parse_adac_configuration(config, None).unwrap();
        assert_eq!(c.format_version, AdacVersion { major: 1, minor: 0 });
        assert_eq!(c.role, CertificateRole::AdacCrtRoleLeaf);
        assert_eq!(c.usage, CertificateUsage::AdacUsageNeutral);
        assert_eq!(c.soc_id, [0x0u8; 16]);
        assert_eq!(
            c.permissions_mask,
            0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFFu128.to_le_bytes()
        );

        let c = parse_adac_configuration(config, Some("root".to_string())).unwrap();
        assert_eq!(c.role, CertificateRole::AdacCrtRoleRoot);
        assert_eq!(c.soc_id, [0x0u8; 16]);
        assert_eq!(
            c.permissions_mask,
            0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFFu128.to_le_bytes()
        );

        let c = parse_adac_configuration(config, Some("intermediate".to_string())).unwrap();
        assert_eq!(c.role, CertificateRole::AdacCrtRoleInt);
        assert_eq!(c.usage, CertificateUsage::AdacUsageStandard);
        assert_eq!(c.soc_id, [0x0u8; 16]);
        assert_eq!(
            c.permissions_mask,
            0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFFu128.to_le_bytes()
        );

        let c = parse_adac_configuration(config, Some("extensions".to_string())).unwrap();
        assert_eq!(
            c.soc_id,
            0x00112233445566778899AABB00000000u128.to_le_bytes()
        );
        assert_eq!(
            c.permissions_mask,
            0x000000000FFFFFFFFFFFFFFFFFFFFFFFFu128.to_le_bytes()
        );
        assert_eq!(
            c.extensions,
            hex::decode("0102030405060708090a0b0c0d0e0f").unwrap()
        );
    }

    #[test]
    fn token_config() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 0
requested_permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"

[token]
version_minor = 1
requested_permissions = "0x00000000FFFFFFFFFFFFFFFFFFFFFFFF"
extensions = "0x01020304"
"#;

        let c = parse_adac_token_configuration(config, None).unwrap();
        assert_eq!(c.format_version, AdacVersion { major: 1, minor: 0 });
        assert_eq!(
            c.requested_permissions,
            0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFFu128.to_le_bytes()
        );
        assert!(c.extensions.is_empty());

        let c = parse_adac_token_configuration(config, Some("token".to_string())).unwrap();
        assert_eq!(c.format_version, AdacVersion { major: 1, minor: 1 });
        assert_eq!(
            c.requested_permissions,
            0x00000000FFFFFFFFFFFFFFFFFFFFFFFFu128.to_le_bytes()
        );
        assert_eq!(c.extensions, hex::decode("01020304").unwrap());
    }

    #[test]
    fn token_config_requires_requested_permissions() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 0
"#;

        let err = parse_adac_token_configuration(config, None).unwrap_err();
        assert!(matches!(
            err,
            AdacError::Encoding(message)
                if message == "Missing default 'requested_permissions' value"
        ));
    }

    #[test]
    fn token_config_rejects_invalid_requested_permissions_length() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 0
requested_permissions = "0xAA"
"#;

        let err = parse_adac_token_configuration(config, None).unwrap_err();
        assert!(matches!(
            err,
            AdacError::Encoding(message)
                if message == "Length for default 'requested_permissions' is invalid"
        ));
    }
}
