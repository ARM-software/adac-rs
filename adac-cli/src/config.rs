// Copyright (c) 2019-2026, Arm Limited. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use adac::{AdacError, AdacVersion, CertificateRole, CertificateUsage};
use toml::{Table, Value};

const EXTENSION_TYPE_SOC_ID: u16 = 0x0004;
const EXTENSION_TYPE_TARGET_IDENTITY: u16 = 0x0005;
const EXTENSION_TYPE_SW_PARTITION_ID: u16 = 0x0009;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ExtensionContext {
    Certificate,
    Token,
}

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

    let soc_id = parse_hex_u128_field(id, "default 'soc_id'")?;

    let permissions = defaults
        .get("permissions_mask")
        .ok_or(AdacError::Encoding(
            "Missing default 'permissions_mask' value".to_string(),
        ))?
        .as_str()
        .ok_or(AdacError::Encoding(
            "Value for default 'permissions_mask' is not String".to_string(),
        ))?;

    let permissions_mask = parse_hex_u128_field(permissions, "default 'permissions_mask'")?;

    let extensions = defaults.get("extensions").ok_or(AdacError::Encoding(
        "Missing default 'extensions' value".to_string(),
    ))?;
    let extensions = parse_extensions_field(
        extensions,
        "default 'extensions'",
        ExtensionContext::Certificate,
    )?;

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
        None => {
            validate_certificate_config(&c)?;
            return Ok(c);
        }
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
        if major != 1 {
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
        c.soc_id = parse_hex_u128_field(soc_id, "'soc_id'")?;
    }

    if let Some(permissions_mask) = sec.get("permissions_mask") {
        let permissions_mask = permissions_mask.as_str().ok_or(AdacError::Encoding(
            "Value for 'permissions_mask' is not String".to_string(),
        ))?;
        c.permissions_mask = parse_hex_u128_field(permissions_mask, "'permissions_mask'")?;
    }

    if let Some(extensions) = sec.get("extensions") {
        c.extensions =
            parse_extensions_field(extensions, "'extensions'", ExtensionContext::Certificate)?;
    }

    validate_certificate_config(&c)?;
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
        parse_hex_u128_field(requested_permissions, "default 'requested_permissions'")?;

    let extensions =
        parse_optional_extensions(defaults, "default 'extensions'", ExtensionContext::Token)?;

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
        if major != 1 {
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
            parse_hex_u128_field(requested_permissions, "'requested_permissions'")?;
    }

    if sec.get("extensions").is_some() {
        c.extensions = parse_optional_extensions(sec, "'extensions'", ExtensionContext::Token)?;
    }

    Ok(c)
}

fn parse_base16_bytes_field(value: &str, field: &str) -> Result<Vec<u8>, AdacError> {
    if value.is_empty() {
        return Ok(vec![]);
    }
    if value.starts_with("0x") || value.starts_with("0X") {
        return Err(AdacError::Encoding(format!(
            "Value for {} must not start with '0x'",
            field
        )));
    }

    hex::decode(value).map_err(|_| {
        AdacError::Encoding(format!(
            "Value for {} is not properly base16 encoded",
            field
        ))
    })
}

fn parse_hex_u128_field(value: &str, field: &str) -> Result<[u8; 16], AdacError> {
    let Some(value) = value.strip_prefix("0x") else {
        return Err(AdacError::Encoding(format!(
            "Value for {} must start with '0x'",
            field
        )));
    };

    let bytes = hex::decode(value).map_err(|_| {
        AdacError::Encoding(format!(
            "Value for {} is not properly hexadecimal encoded",
            field
        ))
    })?;
    if bytes.len() != 16 {
        return Err(AdacError::Encoding(format!(
            "Length for {} is invalid",
            field
        )));
    }

    let value = u128::from_be_bytes(bytes.as_slice().try_into().unwrap());
    Ok(value.to_le_bytes())
}

fn parse_optional_extensions(
    table: &Value,
    field: &str,
    context: ExtensionContext,
) -> Result<Vec<u8>, AdacError> {
    let Some(extensions) = table.get("extensions") else {
        return Ok(vec![]);
    };
    parse_extensions_field(extensions, field, context)
}

fn parse_extensions_field(
    value: &Value,
    field: &str,
    context: ExtensionContext,
) -> Result<Vec<u8>, AdacError> {
    match value {
        Value::String(value) if value.contains(':') => {
            parse_structured_extension(value, field, context)
        }
        Value::String(value) => parse_legacy_extension_tlv_sequence(value, field),
        Value::Array(values) => {
            let mut extensions = Vec::new();
            for (i, value) in values.iter().enumerate() {
                let item_field = format!("{field}[{i}]");
                let value = value.as_str().ok_or(AdacError::Encoding(format!(
                    "Value for {item_field} is not String"
                )))?;
                extensions.extend(parse_single_extension(value, &item_field, context)?);
            }
            Ok(extensions)
        }
        _ => Err(AdacError::Encoding(format!(
            "Value for {field} is not String or Array"
        ))),
    }
}

fn parse_single_extension(
    value: &str,
    field: &str,
    context: ExtensionContext,
) -> Result<Vec<u8>, AdacError> {
    if value.contains(':') {
        parse_structured_extension(value, field, context)
    } else {
        parse_legacy_single_tlv(value, field)
    }
}

fn parse_legacy_extension_tlv_sequence(value: &str, field: &str) -> Result<Vec<u8>, AdacError> {
    let extensions = parse_base16_bytes_field(value, field)?;
    validate_extension_tlv_sequence(&extensions, field)?;
    Ok(extensions)
}

fn parse_legacy_single_tlv(value: &str, field: &str) -> Result<Vec<u8>, AdacError> {
    let extension = parse_base16_bytes_field(value, field)?;
    let tlvs = validate_extension_tlv_sequence(&extension, field)?;
    if tlvs.len() != 1 {
        return Err(AdacError::Encoding(format!(
            "Value for {field} must encode exactly one TLV"
        )));
    }
    Ok(extension)
}

fn validate_extension_tlv_sequence<'a>(
    extensions: &'a [u8],
    field: &str,
) -> Result<Vec<adac::AdacTlv<'a>>, AdacError> {
    adac::parse_tlv_sequence(extensions).map_err(|e| {
        AdacError::Encoding(format!(
            "Value for {field} is not a valid TLV sequence: {e:?}"
        ))
    })
}

fn parse_structured_extension(
    value: &str,
    field: &str,
    context: ExtensionContext,
) -> Result<Vec<u8>, AdacError> {
    let parts = value.split(':').collect::<Vec<_>>();
    let (flags, type_name, value) = match parts.as_slice() {
        [type_name, value] => (0, *type_name, *value),
        ["critical", type_name, value] => (adac::TLV_FLAG_CRITICAL, *type_name, *value),
        _ => {
            return Err(AdacError::Encoding(format!(
                "Value for {field} is not a valid extension"
            )));
        }
    };

    let type_id = parse_extension_type(type_name, field, context)?;
    let value = parse_extension_value(value, field)?;
    validate_known_extension_value(type_id, &value, field)?;

    Ok(adac::tlv_wrap_with_flags(type_id, flags, value.as_slice()))
}

fn parse_extension_type(
    value: &str,
    field: &str,
    context: ExtensionContext,
) -> Result<u16, AdacError> {
    match value {
        "soc_id" if context == ExtensionContext::Token => Ok(EXTENSION_TYPE_SOC_ID),
        "soc_id" => Err(AdacError::Encoding(format!(
            "Value for {field} uses token-only extension 'soc_id'"
        ))),
        "target_identity" => Ok(EXTENSION_TYPE_TARGET_IDENTITY),
        "sw_partition_id" => Ok(EXTENSION_TYPE_SW_PARTITION_ID),
        _ => parse_extension_numeric_type(value, field),
    }
}

fn parse_extension_numeric_type(value: &str, field: &str) -> Result<u16, AdacError> {
    let Some(value) = value.strip_prefix("0x") else {
        return Err(AdacError::Encoding(format!(
            "Value for {field} has invalid extension type"
        )));
    };
    if value.len() != 4 {
        return Err(AdacError::Encoding(format!(
            "Value for {field} extension type must have 4 hexadecimal digits"
        )));
    }
    u16::from_str_radix(value, 16).map_err(|_| {
        AdacError::Encoding(format!(
            "Value for {field} extension type is not properly hexadecimal encoded"
        ))
    })
}

fn parse_extension_value(value: &str, field: &str) -> Result<Vec<u8>, AdacError> {
    if let Some(value) = value.strip_prefix("0x") {
        return parse_extension_integer_value(value, field);
    }
    parse_base16_bytes_field(value, field)
}

fn parse_extension_integer_value(value: &str, field: &str) -> Result<Vec<u8>, AdacError> {
    if !matches!(value.len(), 2 | 4 | 8 | 16 | 32) {
        return Err(AdacError::Encoding(format!(
            "Integer value for {field} must have 2, 4, 8, 16, or 32 hexadecimal digits"
        )));
    }
    let mut bytes = hex::decode(value).map_err(|_| {
        AdacError::Encoding(format!(
            "Integer value for {field} is not properly hexadecimal encoded"
        ))
    })?;
    bytes.reverse();
    Ok(bytes)
}

fn validate_known_extension_value(
    type_id: u16,
    value: &[u8],
    field: &str,
) -> Result<(), AdacError> {
    if type_id == EXTENSION_TYPE_SOC_ID && value.len() != 16 {
        return Err(AdacError::Encoding(format!(
            "Value for {field} soc_id extension must be 16 bytes"
        )));
    }
    Ok(())
}

fn validate_certificate_config(config: &AdacCertificateConfig) -> Result<(), AdacError> {
    if config.format_version.major != 1 || config.format_version.minor > 1 {
        return Err(AdacError::Encoding(
            "Invalid values for version".to_string(),
        ));
    }
    if config.format_version == (AdacVersion { major: 1, minor: 0 }) && config.policies != 0 {
        return Err(AdacError::Encoding(
            "Value for 'policies' is only valid for version 1.1".to_string(),
        ));
    }
    Ok(())
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
extensions = "0000341201000000aa000000"
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
            hex::decode("0000341201000000aa000000").unwrap()
        );
    }

    #[test]
    fn certificate_config_accepts_policies_for_version_1_1() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 1
role = 3
usage = 0
policies = 0x12
lifecycle = 0
oem_constraint = 0
soc_class = 0
soc_id = "0x00000000000000000000000000000000"
permissions_mask = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = ""
"#;

        let c = parse_adac_configuration(config, None).unwrap();

        assert_eq!(c.policies, 0x12);
    }

    #[test]
    fn certificate_config_rejects_policies_for_version_1_0() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 0
role = 3
usage = 0
policies = 1
lifecycle = 0
oem_constraint = 0
soc_class = 0
soc_id = "0x00000000000000000000000000000000"
permissions_mask = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = ""
"#;

        let err = parse_adac_configuration(config, None).unwrap_err();

        assert!(matches!(
            err,
            AdacError::Encoding(message)
                if message == "Value for 'policies' is only valid for version 1.1"
        ));
    }

    #[test]
    fn certificate_config_rejects_section_version_major_zero() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 1
role = 3
usage = 0
lifecycle = 0
oem_constraint = 0
soc_class = 0
soc_id = "0x00000000000000000000000000000000"
permissions_mask = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = ""

[bad]
version_major = 0
"#;

        let err = parse_adac_configuration(config, Some("bad".to_string())).unwrap_err();

        assert!(matches!(
            err,
            AdacError::Encoding(message) if message == "Invalid values for version_major"
        ));
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
extensions = "0000341201000000aa000000"
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
        assert_eq!(
            c.extensions,
            hex::decode("0000341201000000aa000000").unwrap()
        );
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

    #[test]
    fn token_config_rejects_uppercase_integer_prefix() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 0
requested_permissions = "0XAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
"#;

        let err = parse_adac_token_configuration(config, None).unwrap_err();
        assert!(matches!(
            err,
            AdacError::Encoding(message)
                if message == "Value for default 'requested_permissions' must start with '0x'"
        ));
    }

    #[test]
    fn token_config_rejects_section_version_major_zero() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 0
requested_permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"

[bad]
version_major = 0
"#;

        let err = parse_adac_token_configuration(config, Some("bad".to_string())).unwrap_err();

        assert!(matches!(
            err,
            AdacError::Encoding(message) if message == "Invalid values for version_major"
        ));
    }

    #[test]
    fn certificate_config_accepts_structured_extension_array() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 1
role = 3
usage = 0
lifecycle = 0
oem_constraint = 0
soc_class = 0
soc_id = "0x00000000000000000000000000000000"
permissions_mask = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = [
    "0000341201000000aa000000",
    "critical:target_identity:c32e95a1643f7afe",
    "0x0003:0x01020304",
]
"#;

        let c = parse_adac_configuration(config, None).unwrap();

        let mut expected = adac::tlv_wrap(0x1234, vec![0xaa]);
        expected.extend(adac::tlv_wrap_with_flags(
            EXTENSION_TYPE_TARGET_IDENTITY,
            adac::TLV_FLAG_CRITICAL,
            hex::decode("c32e95a1643f7afe").unwrap().as_slice(),
        ));
        expected.extend(adac::tlv_wrap(0x0003, vec![0x04, 0x03, 0x02, 0x01]));
        assert_eq!(c.extensions, expected);
    }

    #[test]
    fn certificate_config_rejects_soc_id_extension_name() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 1
role = 3
usage = 0
lifecycle = 0
oem_constraint = 0
soc_class = 0
soc_id = "0x00000000000000000000000000000000"
permissions_mask = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = "soc_id:00112233445566778899aabbccddeeff"
"#;

        let err = parse_adac_configuration(config, None).unwrap_err();

        assert!(matches!(
            err,
            AdacError::Encoding(message)
                if message == "Value for default 'extensions' uses token-only extension 'soc_id'"
        ));
    }

    #[test]
    fn token_config_accepts_structured_soc_id_extension() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 1
requested_permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = "critical:soc_id:3be6e4b3ae8692b396ed1a8e0d0c0b0a"
"#;

        let c = parse_adac_token_configuration(config, None).unwrap();

        assert_eq!(
            c.extensions,
            adac::tlv_wrap_with_flags(
                EXTENSION_TYPE_SOC_ID,
                adac::TLV_FLAG_CRITICAL,
                hex::decode("3be6e4b3ae8692b396ed1a8e0d0c0b0a")
                    .unwrap()
                    .as_slice(),
            )
        );
    }

    #[test]
    fn extension_array_item_must_be_single_tlv() {
        let mut two_tlvs = adac::tlv_wrap(0x1234, vec![0xaa]);
        two_tlvs.extend(adac::tlv_wrap(0x1235, vec![0xbb]));
        let config = format!(
            r#"
[defaults]
version_major = 1
version_minor = 1
requested_permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = ["{}"]
"#,
            base16ct::lower::encode_string(two_tlvs.as_slice())
        );

        let err = parse_adac_token_configuration(&config, None).unwrap_err();

        assert!(matches!(
            err,
            AdacError::Encoding(message)
                if message == "Value for default 'extensions'[0] must encode exactly one TLV"
        ));
    }

    #[test]
    fn extension_integer_value_requires_supported_width() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 1
requested_permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = "0x0003:0x010203"
"#;

        let err = parse_adac_token_configuration(config, None).unwrap_err();

        assert!(matches!(
            err,
            AdacError::Encoding(message)
                if message == "Integer value for default 'extensions' must have 2, 4, 8, 16, or 32 hexadecimal digits"
        ));
    }

    #[test]
    fn extension_legacy_string_must_be_tlv_sequence() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 0
requested_permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = "01020304"
"#;

        let err = parse_adac_token_configuration(config, None).unwrap_err();

        assert!(matches!(
            err,
            AdacError::Encoding(message)
                if message == "Value for default 'extensions' is not a valid TLV sequence: InvalidLength"
        ));
    }

    #[test]
    fn token_config_rejects_prefixed_extensions() {
        let config = r#"
[defaults]
version_major = 1
version_minor = 0
requested_permissions = "0xAAAAAAAAFFFFFFFFFFFFFFFFFFFFFFFF"
extensions = "0x01020304"
"#;

        let err = parse_adac_token_configuration(config, None).unwrap_err();
        assert!(matches!(
            err,
            AdacError::Encoding(message)
                if message == "Value for default 'extensions' must not start with '0x'"
        ));
    }
}
